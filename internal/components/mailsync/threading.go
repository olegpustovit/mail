package mailsync

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/olegpustovit/mail/imap"
)

type threadNode struct {
	Key        string
	Owner      string
	Account    string
	Identifier string
	Thread     string
}

type threadUnion map[string]string

func (u threadUnion) root(id string) string {
	parent, ok := u[id]
	if !ok {
		u[id] = id
		return id
	}
	if parent != id {
		u[id] = u.root(parent)
	}
	return u[id]
}
func (u threadUnion) join(a, b string) {
	a = u.root(a)
	b = u.root(b)
	if a < b {
		u[b] = a
	} else {
		u[a] = b
	}
}

// Batch reference containers keep child-before-parent imports and cycles stable.
// Metadata and nodes are read/written in batches, including during initial import.
func (s *Service) prepareBatch(ctx context.Context, owner, account string, emails []imap.Email) ([]Metadata, []Change, error) {
	ids := map[string]string{}
	subjects := []string{}
	anchors := make([]string, len(emails))
	keys := make([]string, len(emails))
	oldRoots := map[string]bool{}
	union := threadUnion{}
	earliest, latest := time.Now().UTC(), time.Time{}
	for i := range emails {
		email := &emails[i]
		email.BodyPlain = ""
		email.BodyHTML = ""
		email.Date = email.Date.UTC()
		email.Flags = slices.Clone(email.Flags)
		slices.Sort(email.Flags)
		email.MessageID = strings.Trim(strings.TrimSpace(email.MessageID), "<>")
		keys[i] = messageKey(owner, account, email.Folder, email.UIDValidity, email.ID)
		anchors[i] = identity(owner, account, keys[i])
		if email.MessageID != "" {
			anchors[i] = identity(owner, account, email.MessageID)
			ids[email.MessageID] = anchors[i]
		}
		union.root(anchors[i])
		for n, reference := range email.References {
			reference = strings.Trim(strings.TrimSpace(reference), "<>")
			email.References[n] = reference
			if reference != "" {
				node := identity(owner, account, reference)
				ids[reference] = node
				union.join(anchors[i], node)
			}
		}
		if subject := normalizeSubject(email.Subject); subject != "" {
			subjects = append(subjects, identity(subject))
		}
		if email.Date.Before(earliest) {
			earliest = email.Date
		}
		if email.Date.After(latest) {
			latest = email.Date
		}
	}
	nodeKeys := make([]string, 0, len(ids))
	identifiers := make([]string, 0, len(ids))
	for id, key := range ids {
		nodeKeys = append(nodeKeys, key)
		identifiers = append(identifiers, id)
	}
	for start := 0; start < len(nodeKeys); start += 5000 {
		rows, err := s.pool.Query(ctx, `SELECT id, thread FROM mail_thread_nodes WHERE owner = $1 AND account = $2 AND id = ANY($3)`, owner, account, nodeKeys[start:min(start+5000, len(nodeKeys))])
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var node threadNode
			if err = rows.Scan(&node.Key, &node.Thread); err != nil {
				rows.Close()
				return nil, nil, err
			}
			union.join(node.Key, node.Thread)
			oldRoots[node.Thread] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, nil, err
		}
	}
	// Bridge metadata also repairs an interrupted import that already updated nodes.
	rows, err := s.pool.Query(ctx, `SELECT thread_id, message_id, date, subject_key FROM mail_messages WHERE owner = $1 AND account = $2 AND (key = ANY($3) OR message_id = ANY($4) OR (subject_key = ANY($5) AND date >= $6 AND date <= $7))`,
		owner, account, keys, identifiers, subjects, earliest.AddDate(0, 0, -30), latest.AddDate(0, 0, 30))
	if err != nil {
		return nil, nil, err
	}
	var peers []Metadata
	for rows.Next() {
		var peer Metadata
		if err = rows.Scan(&peer.ThreadID, &peer.MessageID, &peer.Date, &peer.SubjectKey); err != nil {
			rows.Close()
			return nil, nil, err
		}
		peers = append(peers, peer)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	bySubject := map[string][]Metadata{}
	for _, peer := range peers {
		if peer.ThreadID == "" {
			continue
		}
		oldRoots[peer.ThreadID] = true
		if key, ok := ids[peer.MessageID]; ok {
			union.join(key, peer.ThreadID)
		}
		bySubject[peer.SubjectKey] = append(bySubject[peer.SubjectKey], peer)
	}
	for i, email := range emails {
		subject := identity(normalizeSubject(email.Subject))
		if len(email.References) == 0 && normalizeSubject(email.Subject) != "" {
			for _, peer := range bySubject[subject] {
				if !peer.Date.Before(email.Date.AddDate(0, 0, -30)) && !peer.Date.After(email.Date.AddDate(0, 0, 30)) {
					union.join(anchors[i], peer.ThreadID)
				}
			}
		}
		bySubject[subject] = append(bySubject[subject], Metadata{Email: imap.Email{ThreadID: anchors[i], Date: email.Date}})
	}
	batch := &pgx.Batch{}
	mergedRoots := []string{}
	rootTargets := map[string]string{}
	for root := range oldRoots {
		target := union.root(root)
		if target != root {
			mergedRoots = append(mergedRoots, root)
			rootTargets[root] = target
			batch.Queue(`UPDATE mail_thread_nodes SET thread = $4 WHERE owner = $1 AND account = $2 AND thread = $3`, owner, account, root, target)
		}
	}
	for id, key := range ids {
		node := threadNode{Key: key, Owner: owner, Account: account, Identifier: id, Thread: union.root(key)}
		batch.Queue(`INSERT INTO mail_thread_nodes (id, owner, account, identifier, thread) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET owner = EXCLUDED.owner, account = EXCLUDED.account, identifier = EXCLUDED.identifier, thread = EXCLUDED.thread`, node.Key, node.Owner, node.Account, node.Identifier, node.Thread)
	}
	if err = s.sendBatch(ctx, batch); err != nil {
		return nil, nil, err
	}
	merged := []Change{}
	if len(mergedRoots) > 0 {
		mail, err := s.metadata(ctx, owner, account, "thread_id = ANY($3)", []any{mergedRoots}, "", 0)
		if err != nil {
			return nil, nil, err
		}
		for _, old := range mail {
			next := old
			next.ThreadID = rootTargets[old.ThreadID]
			next.Fingerprint = metadataFingerprint(next.Email)
			merged = append(merged, Change{Entity: "msg", Op: "put", Key: next.Key, Message: &next})
		}
	}
	prepared := make([]Metadata, len(emails))
	for i, email := range emails {
		email.ThreadID = union.root(anchors[i])
		prepared[i] = Metadata{Key: keys[i], Owner: owner, Account: account, Email: email, SubjectKey: identity(normalizeSubject(email.Subject)), Fingerprint: metadataFingerprint(email)}
	}
	return prepared, merged, nil
}

func (s *Service) Thread(ctx context.Context, owner, account, thread string) ([]Metadata, error) {
	return s.metadata(ctx, owner, account, "thread_id = $3", []any{thread}, "", 0)
}
