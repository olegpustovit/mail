package mailsync

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/olegpustovit/mail/imap"
	"github.com/olegpustovit/mail/internal/components/auth"
	"github.com/olegpustovit/mail/internal/pg"
)

// ddlMoves covers mail_moves, mail_folder_ops, mail_rule_jobs and mail_rule_applications.
const ddlMoves = `
CREATE TABLE IF NOT EXISTS mail_moves (
	id text PRIMARY KEY, owner text NOT NULL, account text NOT NULL, actor text NOT NULL DEFAULT '',
	transaction text NOT NULL, kind text NOT NULL,
	from_folder text NOT NULL, from_uid text NOT NULL, from_validity bigint NOT NULL,
	target text NOT NULL,
	cur_folder text NOT NULL DEFAULT '', cur_uid text NOT NULL DEFAULT '', cur_validity bigint NOT NULL DEFAULT 0,
	marker text NOT NULL, until timestamptz, state text NOT NULL, return_target text NOT NULL DEFAULT '',
	undo boolean NOT NULL DEFAULT false, cleanup boolean NOT NULL DEFAULT false,
	next_attempt timestamptz, error text NOT NULL DEFAULT '', created timestamptz NOT NULL, expires timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS mail_moves_tx ON mail_moves (owner, account, transaction);
CREATE INDEX IF NOT EXISTS mail_moves_due ON mail_moves (state, next_attempt);
CREATE INDEX IF NOT EXISTS mail_moves_current ON mail_moves (owner, account, cur_folder, cur_validity, cur_uid);
CREATE INDEX IF NOT EXISTS mail_moves_marker ON mail_moves (owner, account, marker);
CREATE INDEX IF NOT EXISTS mail_moves_expires ON mail_moves (expires) WHERE expires IS NOT NULL;

CREATE TABLE IF NOT EXISTS mail_folder_ops (
	id text PRIMARY KEY, owner text NOT NULL, account text NOT NULL, actor text NOT NULL DEFAULT '',
	transaction text NOT NULL, from_name text NOT NULL, to_name text NOT NULL, delimiter text NOT NULL DEFAULT '',
	generations jsonb NOT NULL DEFAULT '{}', validity bigint NOT NULL DEFAULT 0, state text NOT NULL,
	next_attempt timestamptz NOT NULL, created timestamptz NOT NULL, expires timestamptz,
	references_updated boolean NOT NULL DEFAULT false, error text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS mail_folder_ops_scope ON mail_folder_ops (owner, account, state);
CREATE INDEX IF NOT EXISTS mail_folder_ops_due ON mail_folder_ops (state, next_attempt);
CREATE INDEX IF NOT EXISTS mail_folder_ops_expires ON mail_folder_ops (expires) WHERE expires IS NOT NULL;

CREATE TABLE IF NOT EXISTS mail_rule_jobs (
	id text PRIMARY KEY, owner text NOT NULL, account text NOT NULL,
	source_folder text NOT NULL, source_uid text NOT NULL, source_validity bigint NOT NULL, source_key text NOT NULL,
	subject text NOT NULL DEFAULT '', actions jsonb NOT NULL DEFAULT '[]', step int NOT NULL DEFAULT 0,
	state text NOT NULL, created timestamptz NOT NULL, next_attempt timestamptz NOT NULL,
	attempts int NOT NULL DEFAULT 0, error text NOT NULL DEFAULT '', expires timestamptz
);
CREATE INDEX IF NOT EXISTS mail_rule_jobs_due ON mail_rule_jobs (state, next_attempt, created);
CREATE INDEX IF NOT EXISTS mail_rule_jobs_scope ON mail_rule_jobs (owner, account, state);
CREATE INDEX IF NOT EXISTS mail_rule_jobs_expires ON mail_rule_jobs (expires) WHERE expires IS NOT NULL;

CREATE TABLE IF NOT EXISTS mail_rule_applications (
	id text PRIMARY KEY, owner text NOT NULL, account text NOT NULL, rules jsonb,
	folder text NOT NULL, validity bigint NOT NULL, max_uid bigint NOT NULL, after text NOT NULL DEFAULT '',
	scanned int NOT NULL DEFAULT 0, matched int NOT NULL DEFAULT 0, state text NOT NULL,
	error text NOT NULL DEFAULT '', created timestamptz NOT NULL, next_attempt timestamptz, expires timestamptz
);
CREATE INDEX IF NOT EXISTS mail_rule_applications_due ON mail_rule_applications (state, created);
CREATE INDEX IF NOT EXISTS mail_rule_applications_scope ON mail_rule_applications (owner, account);
CREATE INDEX IF NOT EXISTS mail_rule_applications_expires ON mail_rule_applications (expires) WHERE expires IS NOT NULL;
`

// sweepMoves are the TTL deletes for pg.Sweep (one statement each).
var sweepMoves = []string{
	"DELETE FROM mail_moves WHERE expires < now()",
	"DELETE FROM mail_folder_ops WHERE expires < now()",
	"DELETE FROM mail_rule_jobs WHERE expires < now()",
	"DELETE FROM mail_rule_applications WHERE expires < now()",
}

type Move struct {
	ID           string        `json:"id"`
	Owner        string        `json:"-"`
	Account      string        `json:"-"`
	Transaction  string        `json:"transaction"`
	Actor        string        `json:"actor"`
	Kind         string        `json:"kind"`
	From         imap.Location `json:"from"`
	Target       string        `json:"target"`
	Current      imap.Location `json:"current"`
	Marker       string        `json:"-"`
	Until        *time.Time    `json:"until"`
	State        string        `json:"state"`
	ReturnTarget string        `json:"-"`
	Undo         bool          `json:"-"`
	Cleanup      bool          `json:"-"`
	NextAttempt  *time.Time    `json:"-"`
	Error        string        `json:"error,omitempty"`
	Created      time.Time     `json:"created"`
	Expires      *time.Time    `json:"-"`
}

const moveColumns = "id, owner, account, actor, transaction, kind, from_folder, from_uid, from_validity, target, cur_folder, cur_uid, cur_validity, marker, until, state, return_target, undo, cleanup, next_attempt, error, created, expires"

// fields lists pointers in moveColumns order, for both Scan and query arguments.
func (j *Move) fields() []any {
	return []any{&j.ID, &j.Owner, &j.Account, &j.Actor, &j.Transaction, &j.Kind, &j.From.Folder, &j.From.ID, &j.From.Validity, &j.Target, &j.Current.Folder, &j.Current.ID, &j.Current.Validity, &j.Marker, &j.Until, &j.State, &j.ReturnTarget, &j.Undo, &j.Cleanup, &j.NextAttempt, &j.Error, &j.Created, &j.Expires}
}

// marks returns "$from,...,$to".
func marks(from, to int) string {
	parts := make([]string, 0, to-from+1)
	for i := from; i <= to; i++ {
		parts = append(parts, "$"+strconv.Itoa(i))
	}
	return strings.Join(parts, ",")
}
func (s *Service) loadMove(ctx context.Context, where string, args ...any) (Move, error) {
	var job Move
	err := s.pool.QueryRow(ctx, "SELECT "+moveColumns+" FROM mail_moves WHERE "+where+" LIMIT 1", args...).Scan(job.fields()...)
	return job, err
}

// saveMove replaces every mutable column of an existing relocation.
func (s *Service) saveMove(ctx context.Context, job Move) error {
	_, err := s.pool.Exec(ctx, "UPDATE mail_moves SET ("+moveColumns[strings.Index(moveColumns, "actor"):]+") = ("+marks(4, 23)+") WHERE id=$1 AND owner=$2 AND account=$3", job.fields()...)
	return err
}

func validLocation(location imap.Location) bool {
	uid, err := strconv.ParseUint(location.ID, 10, 32)
	return err == nil && uid > 0 && location.Validity > 0 && validMailbox(location.Folder)
}
func validMailbox(name string) bool {
	return name != "" && len(name) <= 1000 && !strings.ContainsAny(name, "\r\n\x00")
}
func validSnooze(until *time.Time) bool {
	return until == nil || until.After(time.Now()) && until.Before(time.Now().AddDate(1, 0, 0))
}
func (s *Service) move(ctx context.Context, owner, account, actor, transaction string, from imap.Location, target, kind string, until *time.Time) error {
	if !validLocation(from) || !validMailbox(target) || from.Folder == target && kind != "snooze" || kind == "snooze" && !validSnooze(until) {
		return errors.New("invalid relocation or snooze time")
	}
	if transaction == "" {
		transaction = auth.Random()
	}
	if len(transaction) > 100 {
		return errors.New("invalid transaction")
	}
	box := &Mailbox{s: s, owner: owner, account: account, actor: actor}
	return s.change(ctx, owner, actor, transaction, nil, func(ctx context.Context) error {
		connection, release, err := s.acquireForActor(ctx, owner, actor)
		if err != nil {
			return err
		}
		defer release()
		if connection.Address != account {
			return errors.New("iCloud account changed")
		}
		if kind == "snooze" {
			folders, err := connection.Mail.ListFolders(ctx)
			if err != nil {
				return err
			}
			found := false
			for _, folder := range folders {
				found = found || folder == target
			}
			if !found {
				if err = connection.Mail.CreateFolder(ctx, target, ""); err != nil {
					return err
				}
			}
		}
		now := time.Now().UTC()
		job := Move{ID: identity(owner, account, transaction), Owner: owner, Account: account, Actor: actor, Transaction: transaction, Kind: kind, From: from, Target: target, Marker: strings.ToLower("$TerminalMail_" + auth.Random()), Until: until, State: "moving", NextAttempt: &now, Created: now}
		_, err = s.pool.Exec(ctx, "INSERT INTO mail_moves ("+moveColumns+") VALUES ("+marks(1, 23)+") ON CONFLICT DO NOTHING", job.fields()...)
		if err != nil {
			return fmt.Errorf("record relocation: %w", err)
		}
		return box.advanceMove(ctx, connection, job.ID)
	})
}
func (m *Mailbox) advanceMove(ctx context.Context, c *Connection, id string) error {
	if err := m.s.checkRenamePending(ctx, m.owner, m.account); err != nil {
		return err
	}
	job, err := m.s.loadMove(ctx, "id=$1 AND owner=$2 AND account=$3", id, m.owner, m.account)
	if err != nil {
		return err
	}
	if c.Address != job.Account {
		return errors.New("iCloud account changed")
	}
	switch job.State {
	case "moving":
		job.Current, err = c.Mail.Relocate(ctx, job.From, job.Target, job.Marker)
		if err == nil && job.Kind == "unsnooze" {
			err = c.Mail.MarkRead(ctx, job.Current.Folder, job.Current.ID, false)
		}
		if err == nil {
			job.State = "moved"
			next := time.Now().Add(14 * 24 * time.Hour)
			job.NextAttempt = &next
			if job.Kind == "snooze" {
				job.State = "snoozed"
				job.NextAttempt = job.Until
			}
		}
	case "waking":
		job.Current, err = c.Mail.Relocate(ctx, job.Current, job.ReturnTarget, job.Marker+"r")
		if err == nil && job.Kind == "snooze" && !job.Undo {
			err = c.Mail.MarkRead(ctx, job.Current.Folder, job.Current.ID, false)
		}
		if err == nil {
			job.State = "awake"
			if job.Undo {
				job.State = "undone"
			}
			job.Cleanup = true
			if err = m.s.saveMove(context.WithoutCancel(ctx), job); err != nil {
				return err
			}
			err = c.Mail.ClearMoveMarker(ctx, job.Current, job.Marker)
			if err == nil {
				err = c.Mail.ClearMoveMarker(ctx, job.Current, job.Marker+"r")
			}
			if err == nil {
				job.Cleanup = false
				job.NextAttempt = nil
				expires := time.Now().Add(14 * 24 * time.Hour)
				job.Expires = &expires
			}
		}
	case "moved":
		if job.NextAttempt == nil || job.NextAttempt.After(time.Now()) {
			return nil
		}
		err = c.Mail.ClearMoveMarker(ctx, job.Current, job.Marker)
		if err == nil {
			job.State = "expired"
			job.NextAttempt = nil
			expires := time.Now().Add(14 * 24 * time.Hour)
			job.Expires = &expires
		}
	case "awake", "undone":
		if !job.Cleanup {
			return nil
		}
		err = c.Mail.ClearMoveMarker(ctx, job.Current, job.Marker)
		if err == nil {
			err = c.Mail.ClearMoveMarker(ctx, job.Current, job.Marker+"r")
		}
		if err == nil {
			job.Cleanup = false
			job.NextAttempt = nil
			expires := time.Now().Add(14 * 24 * time.Hour)
			job.Expires = &expires
		}
	case "snoozed", "expired", "cancelled":
		return nil
	case "failed":
		return imap.ErrLocationChanged
	default:
		return errors.New("unknown relocation state")
	}
	if err != nil {
		next := time.Now().Add(time.Minute)
		problem, state, retry := "Message could not be relocated. It will be checked before retrying.", "", &next
		if errors.Is(err, imap.ErrLocationChanged) || errors.Is(err, imap.ErrMarkerUnsupported) {
			problem, state, retry = "The message location changed or the mailbox cannot retain move markers. Refresh before trying again.", "failed", nil
		}
		_, updateErr := m.s.pool.Exec(context.WithoutCancel(ctx), "UPDATE mail_moves SET error=$4, next_attempt=$5, state=CASE WHEN $6='' THEN state ELSE $6 END WHERE id=$1 AND owner=$2 AND account=$3", job.ID, m.owner, m.account, problem, retry, state)
		return errors.Join(err, updateErr)
	}
	job.Error = ""
	return m.s.saveMove(context.WithoutCancel(ctx), job)
}
func (m *Mailbox) MoveWithValidity(ctx context.Context, from imap.Location, target string) error {
	return m.s.move(ctx, m.owner, m.account, m.actor, transactionID(ctx), from, target, "move", nil)
}
func (m *Mailbox) Snooze(ctx context.Context, from imap.Location, until *time.Time) error {
	if !validSnooze(until) {
		return errors.New("snooze must be in the future and within one year")
	}
	if strings.EqualFold(from.Folder, "Snoozed") {
		if _, err := m.s.snoozedAt(ctx, m.owner, m.account, from); errors.Is(err, pg.ErrNoRows) {
			return m.s.move(ctx, m.owner, m.account, m.actor, transactionID(ctx), from, "Snoozed", "snooze", until)
		} else if err != nil {
			return err
		}
		return m.change(ctx, nil, func(ctx context.Context, c *Connection) error {
			job, err := m.s.snoozedAt(ctx, m.owner, m.account, from)
			if err != nil {
				return err
			}
			result, err := m.s.pool.Exec(ctx, "UPDATE mail_moves SET until=$4, next_attempt=$4 WHERE id=$1 AND owner=$2 AND account=$3 AND state='snoozed'", job.ID, m.owner, m.account, until)
			if err == nil && result.RowsAffected() == 0 {
				return errors.New("snooze changed before rescheduling")
			}
			if err != nil {
				return err
			}
			return m.s.updateSnoozeMetadata(ctx, m.owner, m.account, from, until, m.actor, transactionID(ctx))
		})
	}
	return m.s.move(ctx, m.owner, m.account, m.actor, transactionID(ctx), from, "Snoozed", "snooze", until)
}
func (s *Service) snoozedAt(ctx context.Context, owner, account string, at imap.Location) (Move, error) {
	return s.loadMove(ctx, "owner=$1 AND account=$2 AND kind='snooze' AND state='snoozed' AND cur_folder=$3 AND cur_uid=$4 AND cur_validity=$5", owner, account, at.Folder, at.ID, at.Validity)
}
func (m *Mailbox) returnMove(ctx context.Context, originalTransaction string, undo bool) error {
	id := identity(m.owner, m.account, originalTransaction)
	return m.change(ctx, nil, func(ctx context.Context, c *Connection) error {
		if err := m.advanceMove(ctx, c, id); err != nil {
			return err
		}
		job, err := m.s.loadMove(ctx, "id=$1 AND owner=$2 AND account=$3", id, m.owner, m.account)
		if err != nil {
			return err
		}
		if job.State == "awake" || job.State == "undone" {
			return nil
		}
		if job.State != "waking" {
			if job.State != "moved" && job.State != "snoozed" {
				return errors.New("relocation can no longer be undone")
			}
			now := time.Now()
			target := job.From.Folder
			if job.Kind == "snooze" {
				if strings.EqualFold(target, "Snoozed") {
					target = "INBOX"
				}
				if _, err := c.Mail.UIDValidity(ctx, target); err != nil {
					target = "INBOX"
				}
			}
			if _, err := m.s.pool.Exec(ctx, "UPDATE mail_moves SET state='waking', return_target=$4, undo=$5, next_attempt=$6 WHERE id=$1 AND owner=$2 AND account=$3", id, m.owner, m.account, target, undo, now); err != nil {
				return err
			}
		}
		return m.advanceMove(ctx, c, id)
	})
}
func (m *Mailbox) UndoMove(ctx context.Context, originalTransaction string) error {
	if originalTransaction == "" || len(originalTransaction) > 100 {
		return errors.New("invalid original transaction")
	}
	return m.returnMove(ctx, originalTransaction, true)
}
func (m *Mailbox) Unsnooze(ctx context.Context, from imap.Location) error {
	if !validLocation(from) {
		return errors.New("invalid snoozed message")
	}
	job, err := m.s.snoozedAt(ctx, m.owner, m.account, from)
	if err != nil {
		if errors.Is(err, pg.ErrNoRows) && strings.EqualFold(from.Folder, "Snoozed") {
			return m.s.move(ctx, m.owner, m.account, m.actor, transactionID(ctx), from, "INBOX", "unsnooze", nil)
		}
		return err
	}
	return m.returnMove(ctx, job.Transaction, false)
}
func (s *Service) runMove(ctx context.Context) error {
	job, err := s.loadMove(ctx, "state IN ('moving','waking','moved','snoozed','awake','undone') AND next_attempt <= now() ORDER BY next_attempt")
	if errors.Is(err, pg.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	work, release, allowed, err := s.jobWork(ctx, job.Owner, "mail_moves", job.ID, "next_attempt")
	if err != nil || !allowed {
		return err
	}
	defer release()
	ctx = work
	box := &Mailbox{s: s, owner: job.Owner, account: job.Account, actor: "system"}
	if job.State == "snoozed" {
		err = box.returnMove(ctx, job.Transaction, false)
	} else {
		err = box.change(ctx, nil, func(ctx context.Context, c *Connection) error { return box.advanceMove(ctx, c, job.ID) })
	}
	if err != nil {
		next := time.Now().Add(time.Minute)
		_, updateErr := s.pool.Exec(context.WithoutCancel(ctx), "UPDATE mail_moves SET next_attempt=$4, error=$5 WHERE id=$1 AND owner=$2 AND account=$3 AND state NOT IN ('failed','cancelled')", job.ID, job.Owner, job.Account, next, "Relocation is paused; check the connected account and message location.")
		return errors.Join(err, updateErr, s.reportSnoozeFailure(context.WithoutCancel(ctx), job))
	}
	return nil
}
func (s *Service) decorateMoves(ctx context.Context, owner, account string, mail []Metadata) error {
	type mailbox struct {
		folder   string
		validity uint32
	}
	uids := map[mailbox][]string{}
	markers := map[string]bool{}
	for _, message := range mail {
		box := mailbox{message.Folder, message.UIDValidity}
		uids[box] = append(uids[box], message.ID)
		for _, flag := range message.Flags {
			if strings.HasPrefix(strings.ToLower(flag), "$terminalmail_") {
				markers[flag] = true
			}
		}
	}
	args := []any{owner, account}
	var conditions []string
	for box, ids := range uids {
		args = append(args, box.folder, box.validity, ids)
		n := len(args)
		conditions = append(conditions, fmt.Sprintf("(cur_folder=$%d AND cur_validity=$%d AND cur_uid = ANY($%d))", n-2, n-1, n))
	}
	if len(markers) > 0 {
		values := make([]string, 0, len(markers))
		for marker := range markers {
			values = append(values, marker)
		}
		args = append(args, values)
		conditions = append(conditions, fmt.Sprintf("marker = ANY($%d)", len(args)))
	}
	if len(conditions) == 0 {
		return nil
	}
	rows, err := s.pool.Query(ctx, "SELECT "+moveColumns+" FROM mail_moves WHERE owner=$1 AND account=$2 AND state IN ('snoozed','moved','moving','failed') AND ("+strings.Join(conditions, " OR ")+") ORDER BY created", args...)
	if err != nil {
		return err
	}
	jobs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Move, error) {
		var job Move
		return job, row.Scan(job.fields()...)
	})
	if err != nil {
		return err
	}
	byKey := make(map[string]Move, len(jobs))
	byMarker := make(map[string]Move, len(jobs))
	for _, job := range jobs {
		if job.Current.ID != "" {
			byKey[messageKey(owner, account, job.Current.Folder, job.Current.Validity, job.Current.ID)] = job
		}
		byMarker[job.Marker] = job
	}
	for i := range mail {
		job, ok := byKey[mail[i].Key]
		if !ok {
			for _, flag := range mail[i].Flags {
				if matched, exists := byMarker[flag]; exists && matched.Target == mail[i].Folder {
					job = matched
					ok = true
					break
				}
			}
		}
		if ok {
			mail[i].Snoozed = job.Kind == "snooze"
			if mail[i].Snoozed {
				mail[i].SnoozeUntil = job.Until
				mail[i].SnoozeError = job.Error
			}
			mail[i].MoveTransaction = job.Transaction
			mail[i].MoveActor = job.Actor
		}
	}
	return nil
}
func (s *Service) updateSnoozeMetadata(ctx context.Context, owner, account string, location imap.Location, until *time.Time, actor, tx string) error {
	rows, err := s.metadata(ctx, owner, account, "key = $3", []any{messageKey(owner, account, location.Folder, location.Validity, location.ID)}, "", 1)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return pg.ErrNoRows
	}
	metadata := rows[0]
	metadata.Snoozed = true
	metadata.SnoozeUntil = until
	metadata.SnoozeError = ""
	if err := s.commit(ctx, owner, account, actor, tx, []Change{{Entity: "msg", Op: "put", Key: metadata.Key, Message: &metadata}}); err != nil {
		return err
	}
	return nil
}
func (s *Service) reportSnoozeFailure(ctx context.Context, job Move) error {
	if job.Kind != "snooze" {
		return nil
	}
	mail, err := s.metadata(ctx, job.Owner, job.Account, "$3 = ANY(flags)", []any{job.Marker}, "", 0)
	if err != nil {
		return err
	}
	var changes []Change
	for _, message := range mail {
		if message.SnoozeError != "" {
			continue
		}
		message.SnoozeError = "RETURN: PAUSED // The message or mailbox changed. Use RETURN to choose the current message, or reschedule it."
		changes = append(changes, Change{Entity: "msg", Op: "put", Key: message.Key, Message: &message})
	}
	return s.commit(ctx, job.Owner, job.Account, "system", "", changes)
}
