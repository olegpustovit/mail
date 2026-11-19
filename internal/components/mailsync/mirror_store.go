package mailsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/olegpustovit/mail/imap"
	"github.com/olegpustovit/mail/internal/components/auth"
	"github.com/olegpustovit/mail/internal/pg"
)

type Metadata struct {
	Key     string `json:"key"`
	Owner   string `json:"-"`
	Account string `json:"-"`
	imap.Email
	SubjectKey      string     `json:"-"`
	Fingerprint     string     `json:"-"`
	Version         int64      `json:"syncId"`
	Actor           string     `json:"actor"`
	SentBy          string     `json:"sentBy,omitempty"`
	Snoozed         bool       `json:"snoozed,omitempty"`
	SnoozeUntil     *time.Time `json:"snoozeUntil,omitempty"`
	SnoozeError     string     `json:"snoozeError,omitempty"`
	MoveTransaction string     `json:"moveTransaction,omitempty"`
	MoveActor       string     `json:"moveActor,omitempty"`
	BodyCached      bool       `json:"-"`
	Broken          bool       `json:"-"`
}
type Folder struct {
	Key     string `json:"key"`
	Owner   string `json:"-"`
	Account string `json:"-"`
	imap.FolderInfo
	Imported     int64     `json:"imported"`
	BeforeUID    uint32    `json:"-"`
	Ready        bool      `json:"ready"`
	Complete     bool      `json:"complete"`
	FullFlagSync time.Time `json:"-"`
	Version      int64     `json:"syncId"`
}
type SyncStatus struct {
	Owner    string             `json:"-"`
	Account  string             `json:"-"`
	Phase    string             `json:"phase"`
	Mode     string             `json:"mode"`
	Ready    bool               `json:"ready"`
	Imported int64              `json:"imported"`
	Total    int64              `json:"total"`
	Error    string             `json:"error,omitempty"`
	Quota    *imap.StorageQuota `json:"quota,omitempty"`
	At       time.Time          `json:"at"`
}
type SyncHealth struct {
	LastProgressAgeSec int64  `json:"lastProgressAgeSec"`
	Phase              string `json:"phase"`
	Reconnects1h       int64  `json:"reconnects1h"`
}
type Change struct {
	ID              string        `json:"-"`
	Owner           string        `json:"-"`
	Account         string        `json:"-"`
	Sequence        int64         `json:"syncId"`
	Entity          string        `json:"entity"`
	Op              string        `json:"op"`
	Key             string        `json:"key"`
	Message         *Metadata     `json:"message,omitempty"`
	Before          *Metadata     `json:"before,omitempty"`
	MoveTransaction string        `json:"moveTransaction,omitempty"`
	Folder          *Folder       `json:"folder,omitempty"`
	Status          *SyncStatus   `json:"status,omitempty"`
	Preferences     *Preferences  `json:"preferences,omitempty"`
	Rename          *FolderRename `json:"rename,omitempty"`
	Arrival         bool          `json:"arrival,omitempty"`
	RuleJob         *RuleJob      `json:"-"`
	Actor           string        `json:"actor"`
	TransactionID   string        `json:"txId,omitempty"`
	At              time.Time     `json:"at"`
	Committed       bool          `json:"-"`
}
type ownerState struct {
	generation uint64
	viewers    int
	active     time.Time
	write      sync.Mutex
	changed    chan struct{}
}

func identity(parts ...string) string { raw, _ := json.Marshal(parts); return auth.Hash(string(raw)) }
func messageKey(owner, account, folder string, validity uint32, uid string) string {
	return identity(owner, account, folder, fmt.Sprint(validity), uid)
}
func (s *Service) owner(owner string) *ownerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.owners[owner]
	if state == nil {
		state = &ownerState{changed: make(chan struct{})}
		s.owners[owner] = state
	}
	return state
}
func (s *Service) Changed(owner string) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.owners[owner]
	if state == nil {
		state = &ownerState{changed: make(chan struct{})}
		s.owners[owner] = state
	}
	return state.changed
}
func (s *Service) notify(owner string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state := s.owners[owner]; state != nil {
		close(state.changed)
		state.changed = make(chan struct{})
	}
}
func (s *Service) Done() <-chan struct{} { return s.ctx.Done() }

const ddlMirror = `
CREATE TABLE IF NOT EXISTS mail_messages (
	key text PRIMARY KEY, owner text NOT NULL, account text NOT NULL,
	folder text NOT NULL, uid text NOT NULL, uidvalidity bigint NOT NULL, flags text[], date timestamptz NOT NULL,
	thread_id text NOT NULL, message_id text NOT NULL, subject_key text NOT NULL,
	body_cached boolean NOT NULL DEFAULT false, data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_messages_folder ON mail_messages (owner, account, folder, date DESC);
CREATE INDEX IF NOT EXISTS mail_messages_thread ON mail_messages (owner, account, thread_id);
CREATE INDEX IF NOT EXISTS mail_messages_message_id ON mail_messages (owner, account, message_id);
CREATE INDEX IF NOT EXISTS mail_messages_subject ON mail_messages (owner, account, subject_key, date DESC);
CREATE TABLE IF NOT EXISTS mail_folders (
	id text PRIMARY KEY, owner text NOT NULL, account text NOT NULL, name text NOT NULL, data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_folders_name ON mail_folders (owner, account, name);
CREATE TABLE IF NOT EXISTS mail_sync_status (
	owner text PRIMARY KEY, account text NOT NULL, at timestamptz NOT NULL, data jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS mail_sync_counters (owner text PRIMARY KEY, value bigint NOT NULL);
CREATE TABLE IF NOT EXISTS mail_thread_nodes (
	id text PRIMARY KEY, owner text NOT NULL, account text NOT NULL, identifier text NOT NULL, thread text NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_thread_nodes_thread ON mail_thread_nodes (owner, account, thread);
CREATE TABLE IF NOT EXISTS mail_changelog (
	id text PRIMARY KEY, owner text NOT NULL, account text NOT NULL, seq bigint NOT NULL,
	entity text NOT NULL, op text NOT NULL, key text NOT NULL, move_transaction text NOT NULL DEFAULT '',
	actor text NOT NULL DEFAULT '', tx_id text NOT NULL DEFAULT '', at timestamptz NOT NULL,
	committed boolean NOT NULL DEFAULT false, status_phase text NOT NULL DEFAULT '', data jsonb NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS mail_changelog_seq ON mail_changelog (owner, account, seq);
CREATE INDEX IF NOT EXISTS mail_changelog_at ON mail_changelog (at) WHERE committed;
CREATE INDEX IF NOT EXISTS mail_changelog_uncommitted ON mail_changelog (owner, seq) WHERE NOT committed;
CREATE INDEX IF NOT EXISTS mail_changelog_status ON mail_changelog (entity, status_phase, at);
`

// Committed journal rows expire after 14 days.
const sweepChangelog = `DELETE FROM mail_changelog WHERE committed AND at < now() - interval '14 days'`

// Metadata, Folder, SyncStatus and RuleJob hide internal fields from the API with json:"-";
// the *Doc wrappers add them back under underscore keys so jsonb round-trips every field.
type metaDoc struct {
	Metadata
	O  string `json:"_owner"`
	A  string `json:"_account"`
	SK string `json:"_subjectKey"`
	FP string `json:"_fingerprint"`
	BC bool   `json:"_bodyCached,omitempty"`
	BR bool   `json:"_broken,omitempty"`
}
type folderDoc struct {
	Folder
	O  string    `json:"_owner"`
	A  string    `json:"_account"`
	BU uint32    `json:"_beforeUid"`
	FS time.Time `json:"_fullFlagSync"`
}
type statusDoc struct {
	SyncStatus
	O string `json:"_owner"`
	A string `json:"_account"`
}
type ruleJobDoc struct {
	RuleJob
	O  string     `json:"_owner"`
	A  string     `json:"_account"`
	SK string     `json:"_sourceKey"`
	NA time.Time  `json:"_nextAttempt"`
	N  int        `json:"_attempts"`
	E  *time.Time `json:"_expires"`
}

func toMetaDoc(m Metadata) *metaDoc {
	return &metaDoc{m, m.Owner, m.Account, m.SubjectKey, m.Fingerprint, m.BodyCached, m.Broken}
}
func (d *metaDoc) meta() *Metadata {
	if d == nil {
		return nil
	}
	m := d.Metadata
	m.Owner, m.Account, m.SubjectKey, m.Fingerprint, m.BodyCached, m.Broken = d.O, d.A, d.SK, d.FP, d.BC, d.BR
	return &m
}
func (d *folderDoc) folder() *Folder {
	if d == nil {
		return nil
	}
	f := d.Folder
	f.Owner, f.Account, f.BeforeUID, f.FullFlagSync = d.O, d.A, d.BU, d.FS
	return &f
}
func (d *statusDoc) status() *SyncStatus {
	if d == nil {
		return nil
	}
	v := d.SyncStatus
	v.Owner, v.Account = d.O, d.A
	return &v
}
func (d *ruleJobDoc) job() *RuleJob {
	if d == nil {
		return nil
	}
	j := d.RuleJob
	j.Owner, j.Account, j.SourceKey, j.NextAttempt, j.Attempts, j.Expires = d.O, d.A, d.SK, d.NA, d.N, d.E
	return &j
}

// changeDoc is the jsonb payload of a journal row; scalar Change fields live in columns.
type changeDoc struct {
	Message     *metaDoc      `json:"message,omitempty"`
	Before      *metaDoc      `json:"before,omitempty"`
	Folder      *folderDoc    `json:"folder,omitempty"`
	Status      *statusDoc    `json:"status,omitempty"`
	Preferences *Preferences  `json:"preferences,omitempty"`
	Rename      *FolderRename `json:"rename,omitempty"`
	RuleJob     *ruleJobDoc   `json:"ruleJob,omitempty"`
	Arrival     bool          `json:"arrival,omitempty"`
}

const changeCols = "id, owner, account, seq, entity, op, key, move_transaction, actor, tx_id, at, committed, data"

func scanChange(row pgx.Row) (Change, error) {
	var c Change
	var raw []byte
	if err := row.Scan(&c.ID, &c.Owner, &c.Account, &c.Sequence, &c.Entity, &c.Op, &c.Key, &c.MoveTransaction, &c.Actor, &c.TransactionID, &c.At, &c.Committed, &raw); err != nil {
		return c, err
	}
	c.At = c.At.UTC()
	var d changeDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return c, err
	}
	c.Message, c.Before, c.Folder, c.Status = d.Message.meta(), d.Before.meta(), d.Folder.folder(), d.Status.status()
	c.Preferences, c.Rename, c.RuleJob, c.Arrival = d.Preferences, d.Rename, d.RuleJob.job(), d.Arrival
	return c, nil
}

// queryChanges runs a SELECT of changeCols FROM mail_changelog plus tail.
func (s *Service) queryChanges(ctx context.Context, tail string, args ...any) ([]Change, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+changeCols+" FROM mail_changelog "+tail, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	changes := []Change{}
	for rows.Next() {
		c, err := scanChange(rows)
		if err != nil {
			return nil, err
		}
		changes = append(changes, c)
	}
	return changes, rows.Err()
}

func (s *Service) sendBatch(ctx context.Context, b *pgx.Batch) error {
	if b.Len() == 0 {
		return nil
	}
	br := s.pool.SendBatch(ctx, b)
	defer br.Close()
	for i := 0; i < b.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// loadMessages runs a SELECT of mail_messages rows plus tail (WHERE/ORDER/LIMIT).
func (s *Service) loadMessages(ctx context.Context, tail string, args ...any) ([]Metadata, error) {
	rows, err := s.pool.Query(ctx, "SELECT data, body_cached FROM mail_messages "+tail, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	mail := []Metadata{}
	for rows.Next() {
		var raw []byte
		var cached bool
		if err = rows.Scan(&raw, &cached); err != nil {
			return nil, err
		}
		var d metaDoc
		if err = json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		m := d.meta()
		m.BodyCached = cached
		mail = append(mail, *m)
	}
	return mail, rows.Err()
}

// cacheBody stores a fetched body on its mirror row.
func (s *Service) cacheBody(ctx context.Context, owner, account, key string, email *imap.Email) error {
	images, err := json.Marshal(email.InlineImages)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE mail_messages SET body_cached = true, data = data || jsonb_build_object('bodyPlain', $4::text, 'bodyHTML', $5::text, 'inlineImages', $6::jsonb) WHERE key = $1 AND owner = $2 AND account = $3`, key, owner, account, email.BodyPlain, email.BodyHTML, images)
	return err
}

// A message upsert keeps a cached body (same UIDVALIDITY/UID) while flags and other metadata change.
const upsertMessage = `INSERT INTO mail_messages (key, owner, account, folder, uid, uidvalidity, flags, date, thread_id, message_id, subject_key, body_cached, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (key) DO UPDATE SET owner = EXCLUDED.owner, account = EXCLUDED.account, folder = EXCLUDED.folder, uid = EXCLUDED.uid,
	uidvalidity = EXCLUDED.uidvalidity, flags = EXCLUDED.flags, date = EXCLUDED.date, thread_id = EXCLUDED.thread_id, message_id = EXCLUDED.message_id,
	subject_key = EXCLUDED.subject_key,
	data = EXCLUDED.data || CASE WHEN mail_messages.body_cached THEN jsonb_strip_nulls(jsonb_build_object('bodyPlain', mail_messages.data->'bodyPlain', 'bodyHTML', mail_messages.data->'bodyHTML', 'inlineImages', mail_messages.data->'inlineImages')) ELSE '{}'::jsonb END,
	body_cached = mail_messages.body_cached OR EXCLUDED.body_cached`

// The journal is written before the mirror, then marked visible after applying it.
// Replaying unfinished entries repairs a crash without needing one multi-table transaction.
func (s *Service) commit(ctx context.Context, owner, account, actor, txID string, changes []Change) error {
	if len(changes) == 0 {
		return nil
	}
	state := s.owner(owner)
	state.write.Lock()
	defer state.write.Unlock()
	return s.commitLocked(ctx, owner, account, actor, txID, changes)
}
func (s *Service) commitLocked(ctx context.Context, owner, account, actor, txID string, changes []Change) error {
	if err := s.recoverOwner(ctx, owner); err != nil {
		return err
	}
	var last int64
	err := s.pool.QueryRow(ctx, `INSERT INTO mail_sync_counters (owner, value) VALUES ($1, $2) ON CONFLICT (owner) DO UPDATE SET value = mail_sync_counters.value + $2 RETURNING value`, owner, int64(len(changes))).Scan(&last)
	if err != nil {
		return fmt.Errorf("allocate mail sync IDs: %w", err)
	}
	var relocation Move
	if txID != "" {
		err = s.pool.QueryRow(ctx, "SELECT "+moveColumns+" FROM mail_moves WHERE id = $1 AND owner = $2 AND account = $3 AND state IN ('moved', 'snoozed')", identity(owner, account, txID), owner, account).Scan(relocation.fields()...)
		if err != nil && !errors.Is(err, pg.ErrNoRows) {
			return err
		}
	}
	first := last - int64(len(changes)) + 1
	batch := &pgx.Batch{}
	for i := range changes {
		change := &changes[i]
		change.Owner = owner
		change.Account = account
		change.Sequence = first + int64(i)
		change.ID = identity(owner, fmt.Sprint(change.Sequence))
		change.Actor = actor
		change.TransactionID = txID
		change.At = time.Now().UTC()
		change.Committed = false
		if change.Op == "del" && change.Before != nil && relocation.ID != "" && change.Before.Folder == relocation.From.Folder && change.Before.ID == relocation.From.ID && change.Before.UIDValidity == relocation.From.Validity {
			change.MoveTransaction = relocation.Transaction
		}
		if change.Message != nil {
			copy := *change.Message
			fresh := copy.Version == 0
			copy.Version = change.Sequence
			copy.Actor = actor
			if change.Arrival && copy.MoveActor == "" {
				copy.Actor, change.Actor, change.TransactionID = "imap", "imap", ""
			}
			if fresh && strings.HasPrefix(actor, "mcp:") && (strings.EqualFold(copy.Folder, "Sent Messages") || strings.EqualFold(copy.Folder, "Sent")) {
				copy.SentBy = actor
			}
			if fresh && copy.MoveActor != "" {
				copy.Actor = copy.MoveActor
				change.Actor = copy.MoveActor
				change.MoveTransaction = copy.MoveTransaction
			}
			change.Message = &copy
		}
		if change.Folder != nil {
			copy := *change.Folder
			copy.Version = change.Sequence
			change.Folder = &copy
		}
		d := changeDoc{Preferences: change.Preferences, Rename: change.Rename, Arrival: change.Arrival}
		phase := ""
		if change.Message != nil {
			d.Message = toMetaDoc(*change.Message)
		}
		if change.Before != nil {
			d.Before = toMetaDoc(*change.Before)
		}
		if change.Folder != nil {
			d.Folder = &folderDoc{*change.Folder, change.Folder.Owner, change.Folder.Account, change.Folder.BeforeUID, change.Folder.FullFlagSync}
		}
		if change.Status != nil {
			d.Status = &statusDoc{*change.Status, change.Status.Owner, change.Status.Account}
			phase = change.Status.Phase
		}
		if j := change.RuleJob; j != nil {
			d.RuleJob = &ruleJobDoc{*j, j.Owner, j.Account, j.SourceKey, j.NextAttempt, j.Attempts, j.Expires}
		}
		raw, err := json.Marshal(d)
		if err != nil {
			return err
		}
		batch.Queue(`INSERT INTO mail_changelog (id, owner, account, seq, entity, op, key, move_transaction, actor, tx_id, at, committed, status_phase, data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false, $12, $13)`,
			change.ID, owner, account, change.Sequence, change.Entity, change.Op, change.Key, change.MoveTransaction, change.Actor, change.TransactionID, change.At, phase, raw)
	}
	if err = s.sendBatch(ctx, batch); err != nil {
		return fmt.Errorf("write mail changelog: %w", err)
	}
	if err = s.applyChanges(ctx, changes); err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE mail_changelog SET committed = true WHERE owner = $1 AND seq >= $2 AND seq <= $3`, owner, first, last)
	if err != nil {
		return fmt.Errorf("commit mail changelog: %w", err)
	}
	s.notify(owner)
	return nil
}
func (s *Service) recoverOwner(ctx context.Context, owner string) error {
	pending, err := s.queryChanges(ctx, `WHERE NOT committed AND ($1 = '' OR owner = $1) ORDER BY owner, seq`, owner)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	if err = s.applyChanges(ctx, pending); err != nil {
		return fmt.Errorf("recover mail journal: %w", err)
	}
	ids := make([]string, len(pending))
	for i, c := range pending {
		ids[i] = c.ID
	}
	_, err = s.pool.Exec(ctx, `UPDATE mail_changelog SET committed = true WHERE id = ANY($1)`, ids)
	return err
}
func (s *Service) applyChanges(ctx context.Context, changes []Change) error {
	b := &pgx.Batch{}
	for _, change := range changes {
		switch change.Entity {
		case "rule-job":
			if err := s.sendBatch(ctx, b); err != nil {
				return err
			}
			b = &pgx.Batch{}
			if change.RuleJob == nil || change.RuleJob.Owner != change.Owner || change.RuleJob.Account != change.Account {
				return errors.New("invalid rule job journal scope")
			}
			if err := s.insertRuleJobs(ctx, []RuleJob{*change.RuleJob}); err != nil {
				return err
			}
			continue
		case "tx", "rename":
			continue
		case "msg", "folder", "status", "pref":
		default:
			return fmt.Errorf("unknown mail journal entity %q", change.Entity)
		}
		if change.Op == "reset" {
			if change.Folder == nil {
				return errors.New("mail folder reset has no folder")
			}
			b.Queue(`DELETE FROM mail_messages WHERE owner = $1 AND account = $2 AND folder = $3`, change.Owner, change.Account, change.Folder.Name)
		}
		if change.Op == "del" {
			switch change.Entity {
			case "msg":
				b.Queue(`DELETE FROM mail_messages WHERE key = $1 AND owner = $2 AND account = $3`, change.Key, change.Owner, change.Account)
			case "folder":
				b.Queue(`DELETE FROM mail_folders WHERE id = $1 AND owner = $2 AND account = $3`, change.Key, change.Owner, change.Account)
			case "status":
				b.Queue(`DELETE FROM mail_sync_status WHERE owner = $1`, change.Owner)
			case "pref":
				b.Queue(`DELETE FROM mail_preferences WHERE id = $1`, change.Owner)
			}
			continue
		}
		switch change.Entity {
		case "msg":
			m := change.Message
			if m == nil || m.Owner != change.Owner || m.Account != change.Account {
				return errors.New("invalid mail message journal scope")
			}
			raw, err := json.Marshal(toMetaDoc(*m))
			if err != nil {
				return err
			}
			b.Queue(upsertMessage, change.Key, m.Owner, m.Account, m.Folder, m.ID, int64(m.UIDValidity), m.Flags, m.Date, m.ThreadID, m.MessageID, m.SubjectKey, m.BodyCached, raw)
		case "folder":
			f := change.Folder
			if f == nil || f.Owner != change.Owner || f.Account != change.Account {
				return errors.New("invalid folder journal scope")
			}
			raw, err := json.Marshal(folderDoc{*f, f.Owner, f.Account, f.BeforeUID, f.FullFlagSync})
			if err != nil {
				return err
			}
			b.Queue(`INSERT INTO mail_folders (id, owner, account, name, data) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET owner = EXCLUDED.owner, account = EXCLUDED.account, name = EXCLUDED.name, data = EXCLUDED.data`, change.Key, f.Owner, f.Account, f.Name, raw)
		case "status":
			st := change.Status
			if st == nil || st.Owner != change.Owner || st.Account != change.Account {
				return errors.New("invalid status journal scope")
			}
			raw, err := json.Marshal(statusDoc{*st, st.Owner, st.Account})
			if err != nil {
				return err
			}
			b.Queue(`INSERT INTO mail_sync_status (owner, account, at, data) VALUES ($1, $2, $3, $4) ON CONFLICT (owner) DO UPDATE SET account = EXCLUDED.account, at = EXCLUDED.at, data = EXCLUDED.data`, change.Owner, st.Account, st.At, raw)
		case "pref":
			if change.Preferences == nil {
				return errors.New("invalid preferences journal entry")
			}
			raw, err := json.Marshal(change.Preferences)
			if err != nil {
				return err
			}
			b.Queue(`INSERT INTO mail_preferences (id, data) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`, change.Owner, raw)
		}
	}
	return s.sendBatch(ctx, b)
}

func (s *Service) acknowledge(ctx context.Context, owner, account, actor, txID string) error {
	if txID == "" {
		return nil
	}
	return s.commit(ctx, owner, account, actor, txID, []Change{{Entity: "tx", Op: "ack", Key: txID}})
}
func (s *Service) TransactionCommitted(ctx context.Context, owner, account, txID string) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `SELECT seq FROM mail_changelog WHERE owner = $1 AND account = $2 AND tx_id = $3 AND entity = 'tx' AND committed LIMIT 1`, owner, account, txID).Scan(&seq)
	if errors.Is(err, pg.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}
func (s *Service) Cursor(ctx context.Context, owner, account string) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `SELECT seq FROM mail_changelog WHERE owner = $1 AND account = $2 AND committed ORDER BY seq DESC LIMIT 1`, owner, account).Scan(&seq)
	if errors.Is(err, pg.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}
func (s *Service) Changes(ctx context.Context, owner, account string, cursor int64) ([]Change, error) {
	return s.queryChanges(ctx, `WHERE owner = $1 AND account = $2 AND committed AND seq > $3 ORDER BY seq LIMIT 1000`, owner, account, cursor)
}

func (s *Service) HistoryMissing(ctx context.Context, owner, account string, cursor int64) (bool, error) {
	if cursor == 0 {
		return false, nil
	}
	var first int64
	err := s.pool.QueryRow(ctx, `SELECT seq FROM mail_changelog WHERE owner = $1 AND account = $2 AND committed ORDER BY seq LIMIT 1`, owner, account).Scan(&first)
	if errors.Is(err, pg.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	last, err := s.Cursor(ctx, owner, account)
	return cursor < first-1 || cursor > last, err
}
func (s *Service) Folders(ctx context.Context, owner, account string) ([]Folder, error) {
	rows, err := s.pool.Query(ctx, `SELECT data FROM mail_folders WHERE owner = $1 AND account = $2 ORDER BY name COLLATE "C"`, owner, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	folders := []Folder{}
	for rows.Next() {
		var d folderDoc
		if err = rows.Scan(&d); err != nil {
			return nil, err
		}
		folders = append(folders, *d.folder())
	}
	return folders, rows.Err()
}
func (s *Service) Status(ctx context.Context, owner, account string) (SyncStatus, error) {
	var d statusDoc
	err := s.pool.QueryRow(ctx, `SELECT data FROM mail_sync_status WHERE owner = $1 AND account = $2`, owner, account).Scan(&d)
	if errors.Is(err, pg.ErrNoRows) {
		return SyncStatus{Owner: owner, Account: account, Phase: "connecting"}, nil
	}
	if err != nil {
		return SyncStatus{}, err
	}
	return *d.status(), nil
}
func (s *Service) SyncHealth(ctx context.Context) (SyncHealth, error) {
	health := SyncHealth{Phase: "idle"}
	rows, err := s.pool.Query(ctx, `SELECT data FROM mail_sync_status`)
	if err != nil {
		return health, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	for rows.Next() {
		var d statusDoc
		if err = rows.Scan(&d); err != nil {
			return health, err
		}
		age := int64(now.Sub(d.At).Seconds())
		if age >= health.LastProgressAgeSec {
			health.LastProgressAgeSec = age
			health.Phase = d.Phase
		}
	}
	if err = rows.Err(); err != nil {
		return health, err
	}
	if health.LastProgressAgeSec > 180 {
		health.Phase = "stalled"
	}
	err = s.pool.QueryRow(ctx, `SELECT count(*) FROM mail_changelog WHERE entity = 'status' AND status_phase = 'reconnecting' AND at >= $1`, now.Add(-time.Hour)).Scan(&health.Reconnects1h)
	return health, err
}

// metadata loads an owner/account's messages; where is extra SQL (args are $3...) or empty; orderBy defaults to newest first.
func (s *Service) metadata(ctx context.Context, owner, account, where string, args []any, orderBy string, limit int64) ([]Metadata, error) {
	q := "WHERE owner = $1 AND account = $2"
	if where != "" {
		q += " AND (" + where + ")"
	}
	if orderBy == "" {
		orderBy = "date DESC, key"
	}
	q += " ORDER BY " + orderBy
	if limit > 0 {
		q += fmt.Sprint(" LIMIT ", limit)
	}
	return s.loadMessages(ctx, q, append([]any{owner, account}, args...)...)
}

// messageByKey returns pg.ErrNoRows when the mirror has no such message.
func (s *Service) messageByKey(ctx context.Context, owner, account, key string) (Metadata, error) {
	rows, err := s.metadata(ctx, owner, account, "key = $3", []any{key}, "", 1)
	if err != nil {
		return Metadata{}, err
	}
	if len(rows) == 0 {
		return Metadata{}, pg.ErrNoRows
	}
	return rows[0], nil
}
func (s *Service) Bootstrap(ctx context.Context, owner, account string) (int64, []Folder, []Metadata, SyncStatus, error) {
	cursor, err := s.Cursor(ctx, owner, account)
	if err != nil {
		return 0, nil, nil, SyncStatus{}, err
	}
	folders, err := s.Folders(ctx, owner, account)
	if err != nil {
		return 0, nil, nil, SyncStatus{}, err
	}
	messages, err := s.metadata(ctx, owner, account, "", nil, "", 2000)
	if err != nil {
		return 0, nil, nil, SyncStatus{}, err
	}
	status, err := s.Status(ctx, owner, account)
	return cursor, folders, messages, status, err
}

func (s *Service) History(ctx context.Context, owner, account string, before time.Time, key string) ([]Metadata, error) {
	if before.IsZero() {
		return s.metadata(ctx, owner, account, "", nil, "", 2000)
	}
	return s.metadata(ctx, owner, account, "date < $3 OR (date = $3 AND key > $4)", []any{before, key}, "", 2000)
}

func normalizeSubject(subject string) string {
	text := strings.TrimSpace(strings.ToLower(subject))
	for {
		old := text
		for _, prefix := range []string{"re:", "fw:", "fwd:"} {
			text = strings.TrimSpace(strings.TrimPrefix(text, prefix))
		}
		if old == text {
			return strings.Join(strings.Fields(text), " ")
		}
	}
}
