package mailsync

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"slices"
	"strings"
	"time"

	"github.com/olegpustovit/mail/imap"
	"github.com/olegpustovit/mail/internal/components/auth"
	"github.com/olegpustovit/mail/internal/pg"
)

type FolderRename struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Delimiter string `json:"delimiter"`
}
type folderOperation struct {
	ID          string
	Owner       string
	Account     string
	Actor       string
	Transaction string
	FolderRename
	Generations       map[string]uint32
	Validity          uint32
	State             string
	NextAttempt       time.Time
	Created           time.Time
	Expires           *time.Time
	ReferencesUpdated bool
	Error             string
}

const opColumns = "id, owner, account, actor, transaction, from_name, to_name, delimiter, generations, validity, state, next_attempt, created, expires, references_updated, error"

// fields lists pointers in opColumns order, for both Scan and query arguments.
func (o *folderOperation) fields() []any {
	return []any{&o.ID, &o.Owner, &o.Account, &o.Actor, &o.Transaction, &o.From, &o.To, &o.Delimiter, &o.Generations, &o.Validity, &o.State, &o.NextAttempt, &o.Created, &o.Expires, &o.ReferencesUpdated, &o.Error}
}
func (s *Service) loadOp(ctx context.Context, where string, args ...any) (folderOperation, error) {
	var op folderOperation
	err := s.pool.QueryRow(ctx, "SELECT "+opColumns+" FROM mail_folder_ops WHERE "+where+" LIMIT 1", args...).Scan(op.fields()...)
	return op, err
}

var ErrRenamePending = errors.New("folder rename recovery is pending")

func (r FolderRename) path(name string) string {
	if name == r.From || r.Delimiter != "" && strings.HasPrefix(name, r.From+r.Delimiter) {
		return r.To + strings.TrimPrefix(name, r.From)
	}
	return name
}
func (m *Mailbox) RenameFolder(ctx context.Context, from, to string) error {
	if !validMailbox(from) || !validMailbox(to) || from == to || strings.EqualFold(from, "INBOX") {
		return errors.New("invalid mailbox rename")
	}
	transaction := transactionID(ctx)
	if transaction == "" {
		transaction = auth.Random()
	}
	return m.changeCommand(ctx, nil, true, func(ctx context.Context, c *Connection) error {
		id := identity(m.owner, m.account, transaction)
		op, err := m.s.loadOp(ctx, "id=$1 AND owner=$2 AND account=$3", id, m.owner, m.account)
		if errors.Is(err, pg.ErrNoRows) {
			folders, err := m.s.Folders(ctx, m.owner, m.account)
			if err != nil {
				return err
			}
			var source *Folder
			for i := range folders {
				f := &folders[i]
				if f.Name == from {
					source = f
				}
				if (f.Name == from || f.Delimiter != "" && strings.HasPrefix(f.Name, from+f.Delimiter)) && f.Role != "" {
					return errors.New("system mailboxes cannot be renamed")
				}
			}
			if source == nil {
				return errors.New("source mailbox missing")
			}
			if source.Delimiter != "" && strings.HasPrefix(to, from+source.Delimiter) {
				return errors.New("mailbox cannot become its own child")
			}
			if err = m.s.checkRenamePending(ctx, m.owner, m.account); err != nil {
				return err
			}
			validity, err := c.Mail.UIDValidity(ctx, from)
			if err != nil {
				return err
			}
			op = folderOperation{ID: id, Owner: m.owner, Account: m.account, Actor: m.actor, Transaction: transaction, FolderRename: FolderRename{From: from, To: to, Delimiter: source.Delimiter}, Validity: validity, State: "pending", NextAttempt: time.Now(), Created: time.Now()}
			op.Generations = map[string]uint32{from: validity}
			names, err := c.Mail.ListFolders(ctx)
			if err != nil {
				return err
			}
			for _, name := range names {
				if name != from && op.path(name) != name {
					generation, generationErr := c.Mail.UIDValidity(ctx, name)
					if generationErr != nil {
						return generationErr
					}
					op.Generations[name] = generation
				}
			}
			if _, err = m.s.pool.Exec(ctx, "INSERT INTO mail_folder_ops ("+opColumns+") VALUES ("+marks(1, 16)+")", op.fields()...); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if op.From != from || op.To != to {
			return errors.New("transaction belongs to another rename")
		}
		return m.s.applyRename(ctx, c, op)
	})
}
func (s *Service) checkRenamePending(ctx context.Context, owner, account string) error {
	var pending bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM mail_folder_ops WHERE owner=$1 AND account=$2 AND state='pending')", owner, account).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrRenamePending
	}
	return nil
}
func (s *Service) applyRename(ctx context.Context, c *Connection, op folderOperation) error {
	if op.State == "done" {
		return nil
	}
	if op.State != "pending" || c.Address != op.Account {
		return errors.New("rename account or state changed")
	}
	names, err := c.Mail.ListFolders(ctx)
	if err != nil {
		return err
	}
	source, target := slices.Contains(names, op.From), slices.Contains(names, op.To)
	if source && !target {
		validity, err := c.Mail.UIDValidity(ctx, op.From)
		if err != nil {
			return err
		}
		if validity != op.Validity {
			return imap.ErrLocationChanged
		}
		if err = c.Mail.RenameFolder(ctx, op.From, op.To); err != nil {
			return err
		}
	} else if source || !target {
		return imap.ErrLocationChanged
	}
	validity, err := c.Mail.UIDValidity(ctx, op.To)
	if err != nil {
		return err
	}
	if validity != op.Validity {
		return imap.ErrLocationChanged
	}
	state := s.owner(op.Owner)
	state.write.Lock()
	defer state.write.Unlock()
	if _, err = s.pool.Exec(ctx, "UPDATE mail_folder_ops SET references_updated=true WHERE id=$1 AND owner=$2 AND account=$3 AND state='pending'", op.ID, op.Owner, op.Account); err != nil {
		return err
	}
	if err = s.rewriteRenameRefs(ctx, op); err != nil {
		return err
	}
	// The path event and preferences share the journal; replay is safe after any interruption.
	if err = s.recoverOwner(ctx, op.Owner); err != nil {
		return err
	}
	prefs, err := s.Preferences(ctx, op.Owner)
	if err != nil {
		return err
	}
	for i := range prefs.Rules {
		for j := range prefs.Rules[i].Actions {
			if prefs.Rules[i].Actions[j].Action == "move" {
				prefs.Rules[i].Actions[j].Target = op.path(prefs.Rules[i].Actions[j].Target)
			}
		}
		if prefs.Rules[i].Action == "move" {
			prefs.Rules[i].Target = op.path(prefs.Rules[i].Target)
		}
	}
	rename := op.FolderRename
	if err = s.commitLocked(ctx, op.Owner, op.Account, op.Actor, op.Transaction, []Change{{Entity: "rename", Op: "put", Key: op.ID, Rename: &rename}, {Entity: "pref", Op: "put", Key: op.Owner, Preferences: &prefs}}); err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, "UPDATE mail_folder_ops SET state='done', expires=$4 WHERE id=$1 AND owner=$2 AND account=$3 AND state='pending'", op.ID, op.Owner, op.Account, time.Now().Add(14*24*time.Hour))
	return err
}
func (s *Service) rewriteRenameRefs(ctx context.Context, op folderOperation) error {
	rows, err := s.pool.Query(ctx, "SELECT "+moveColumns+" FROM mail_moves WHERE owner=$1 AND account=$2", op.Owner, op.Account)
	if err != nil {
		return err
	}
	moves, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Move, error) {
		var job Move
		return job, row.Scan(job.fields()...)
	})
	if err != nil {
		return err
	}
	for _, job := range moves {
		changed := false
		for _, path := range []*string{&job.From.Folder, &job.Target, &job.Current.Folder, &job.ReturnTarget} {
			next := op.path(*path)
			if next != *path {
				*path = next
				changed = true
			}
		}
		if changed {
			if err = s.saveMove(ctx, job); err != nil {
				return err
			}
		}
	}
	ruleRows, err := s.pool.Query(ctx, "SELECT "+ruleJobColumns+" FROM mail_rule_jobs WHERE owner=$1 AND account=$2 AND state IN ('pending','failed')", op.Owner, op.Account)
	if err != nil {
		return err
	}
	ruleJobs, err := pgx.CollectRows(ruleRows, scanRuleJob)
	if err != nil {
		return err
	}
	for _, job := range ruleJobs {
		actions := job.Actions
		for i := range actions {
			if actions[i].Action == "move" {
				actions[i].Target = op.path(actions[i].Target)
			}
		}
		if _, err = s.pool.Exec(ctx, "UPDATE mail_rule_jobs SET source_folder=$4, actions=$5 WHERE id=$1 AND owner=$2 AND account=$3", job.ID, op.Owner, op.Account, op.path(job.Source.Folder), actionRows(actions)); err != nil {
			return err
		}
	}
	appRows, err := s.pool.Query(ctx, "SELECT id, folder, rules FROM mail_rule_applications WHERE owner=$1 AND account=$2 AND state='pending'", op.Owner, op.Account)
	if err != nil {
		return err
	}
	applications, err := pgx.CollectRows(appRows, func(row pgx.CollectableRow) (RuleApplication, error) {
		var job RuleApplication
		return job, row.Scan(&job.ID, &job.Folder, &job.Rules)
	})
	if err != nil {
		return err
	}
	for _, job := range applications {
		for i := range job.Rules {
			if job.Rules[i].Action == "move" {
				job.Rules[i].Target = op.path(job.Rules[i].Target)
			}
			for j := range job.Rules[i].Actions {
				if job.Rules[i].Actions[j].Action == "move" {
					job.Rules[i].Actions[j].Target = op.path(job.Rules[i].Actions[j].Target)
				}
			}
		}
		if _, err = s.pool.Exec(ctx, "UPDATE mail_rule_applications SET folder=$2, rules=$3 WHERE id=$1 AND state='pending'", job.ID, op.path(job.Folder), job.Rules); err != nil {
			return err
		}
	}
	outboxRows, err := s.pool.Query(ctx, "SELECT id, payload FROM mail_outbox WHERE owner=$1 AND account=$2 AND payload IS NOT NULL AND status IN ('pending','sending','uncertain','cancelled','restored')", op.Owner, op.Account)
	if err != nil {
		return err
	}
	outbox, err := pgx.CollectRows(outboxRows, func(row pgx.CollectableRow) (Outbox, error) {
		var job Outbox
		return job, row.Scan(&job.ID, &job.Payload)
	})
	if err != nil {
		return err
	}
	for _, job := range outbox {
		raw, err := s.open(job.Payload)
		if err != nil {
			return err
		}
		var message Send
		if err = json.Unmarshal(raw, &message); err != nil {
			return err
		}
		reply, draft := op.path(message.ReplyFolder), op.path(message.DraftFolder)
		if reply == message.ReplyFolder && draft == message.DraftFolder {
			continue
		}
		message.ReplyFolder, message.DraftFolder = reply, draft
		raw, err = json.Marshal(message)
		if err != nil {
			return err
		}
		if _, err = s.pool.Exec(ctx, "UPDATE mail_outbox SET payload=$5 WHERE id=$1 AND owner=$2 AND account=$3 AND payload=$4", job.ID, op.Owner, op.Account, job.Payload, s.seal(raw)); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) runRename(ctx context.Context) error {
	op, err := s.loadOp(ctx, "state='pending' AND next_attempt <= now() ORDER BY created")
	if errors.Is(err, pg.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	work, release, allowed, err := s.jobWork(ctx, op.Owner, "mail_folder_ops", op.ID, "next_attempt")
	if err != nil || !allowed {
		return err
	}
	defer release()
	ctx = work
	m, err := s.Mailbox(ctx, op.Owner, op.Actor)
	if err == nil && m.account != op.Account {
		_, err = s.pool.Exec(ctx, "UPDATE mail_folder_ops SET state='cancelled', expires=$4 WHERE id=$1 AND owner=$2 AND account=$3 AND state='pending'", op.ID, op.Owner, op.Account, time.Now().Add(14*24*time.Hour))
		return err
	}
	if err == nil {
		err = m.changeCommand(ctx, nil, true, func(ctx context.Context, c *Connection) error { return s.applyRename(ctx, c, op) })
	}
	if err != nil {
		_, updateErr := s.pool.Exec(context.WithoutCancel(ctx), "UPDATE mail_folder_ops SET next_attempt=$2, error=$3 WHERE id=$1 AND state='pending'", op.ID, time.Now().Add(time.Minute), cutText(err.Error(), 500))
		return errors.Join(err, updateErr)
	}
	return nil
}

func (s *Service) remapSendSources(ctx context.Context, owner, account string, message *Send) error {
	rows, err := s.pool.Query(ctx, "SELECT "+opColumns+" FROM mail_folder_ops WHERE owner=$1 AND account=$2 AND state='done' ORDER BY created", owner, account)
	if err != nil {
		return err
	}
	ops, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (folderOperation, error) {
		var op folderOperation
		return op, row.Scan(op.fields()...)
	})
	if err != nil {
		return err
	}
	for _, op := range ops {
		if message.ReplyValidity != 0 && op.Generations[message.ReplyFolder] == message.ReplyValidity {
			message.ReplyFolder = op.path(message.ReplyFolder)
		}
		if message.DraftValidity != 0 && op.Generations[message.DraftFolder] == message.DraftValidity {
			message.DraftFolder = op.path(message.DraftFolder)
		}
	}
	return nil
}
