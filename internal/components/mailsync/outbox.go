package mailsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/olegpustovit/mail/internal/components/auth"
	"github.com/olegpustovit/mail/internal/mailmessage"
	"github.com/olegpustovit/mail/internal/pg"
	"github.com/olegpustovit/mail/smtp"
)

type Send struct {
	To            []string                 `json:"to"`
	CC            []string                 `json:"cc"`
	BCC           []string                 `json:"bcc"`
	Subject       string                   `json:"subject"`
	Body          string                   `json:"body"`
	ReplyFolder   string                   `json:"replyFolder"`
	ReplyID       string                   `json:"replyId"`
	ReplyAll      bool                     `json:"replyAll"`
	SendAt        time.Time                `json:"sendAt"`
	TransactionID string                   `json:"transactionId"`
	DraftID       string                   `json:"draftId"`
	DraftFolder   string                   `json:"draftFolder"`
	DraftValidity uint32                   `json:"draftValidity"`
	ReplyValidity uint32                   `json:"replyValidity"`
	From          string                   `json:"from"`
	HTML          bool                     `json:"html"`
	Automated     bool                     `json:"automated,omitempty"`
	Attachments   []mailmessage.Attachment `json:"attachments"`
}
type Outbox struct {
	ID             string     `json:"id"`
	Owner          string     `json:"-"`
	Account        string     `json:"-"`
	Payload        []byte     `json:"-"`
	SendAt         time.Time  `json:"sendAt"`
	Created        time.Time  `json:"created"`
	Status         string     `json:"status"`
	RetryAt        time.Time  `json:"-"`
	Error          string     `json:"error,omitempty"`
	Message        *Send      `json:"message,omitempty"`
	Actor          string     `json:"actor,omitempty"`
	PayloadExpires *time.Time `json:"-"`
}

const ddlOutbox = `
CREATE TABLE IF NOT EXISTS mail_outbox (
	id text PRIMARY KEY,
	owner text NOT NULL,
	account text NOT NULL,
	payload bytea,
	send_at timestamptz NOT NULL,
	created timestamptz NOT NULL,
	status text NOT NULL,
	retry_at timestamptz NOT NULL DEFAULT 'epoch',
	error text NOT NULL DEFAULT '',
	actor text NOT NULL DEFAULT '',
	payload_expires timestamptz
);
CREATE INDEX IF NOT EXISTS mail_outbox_owner_created ON mail_outbox (owner, created DESC);
CREATE INDEX IF NOT EXISTS mail_outbox_status_send ON mail_outbox (status, send_at);
CREATE INDEX IF NOT EXISTS mail_outbox_payload_expires ON mail_outbox (payload_expires) WHERE payload_expires IS NOT NULL;
CREATE TABLE IF NOT EXISTS mail_push_devices (
	id text PRIMARY KEY,
	owner text NOT NULL,
	account text NOT NULL,
	session text NOT NULL,
	name text NOT NULL,
	zone text NOT NULL,
	payload bytea NOT NULL,
	"cursor" bigint NOT NULL,
	next_attempt timestamptz NOT NULL,
	error text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS mail_push_devices_owner_account ON mail_push_devices (owner, account);
CREATE INDEX IF NOT EXISTS mail_push_devices_next_attempt ON mail_push_devices (next_attempt);
CREATE TABLE IF NOT EXISTS mail_push_keys (
	id text PRIMARY KEY,
	public text NOT NULL,
	private bytea NOT NULL
);
CREATE TABLE IF NOT EXISTS mail_preferences (
	id text PRIMARY KEY,
	data jsonb NOT NULL
);`

// Keep transaction receipts permanently; only old recovered payloads expire.
var sweepOutbox = []string{`UPDATE mail_outbox SET payload = NULL, payload_expires = NULL WHERE status IN ('sent', 'cancelled', 'restored') AND payload_expires <= now()`}

const outboxCols = "id, owner, account, payload, send_at, created, status, retry_at, error, actor, payload_expires"

// scanOutbox reads outboxCols from a pgx row.
func scanOutbox(row interface{ Scan(...any) error }) (Outbox, error) {
	var j Outbox
	err := row.Scan(&j.ID, &j.Owner, &j.Account, &j.Payload, &j.SendAt, &j.Created, &j.Status, &j.RetryAt, &j.Error, &j.Actor, &j.PayloadExpires)
	return j, err
}

// queryOutbox runs a SELECT of outboxCols.
func (s *Service) queryOutbox(ctx context.Context, sql string, args ...any) ([]Outbox, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Outbox, error) { return scanOutbox(r) })
}

func validateSend(m Send) error {
	if err := mailmessage.ValidateAttachments(m.Attachments); err != nil {
		return err
	}
	for _, source := range []struct {
		folder, id string
		validity   uint32
	}{{m.ReplyFolder, m.ReplyID, m.ReplyValidity}, {m.DraftFolder, m.DraftID, m.DraftValidity}} {
		if source.id == "" {
			continue
		}
		uid, err := strconv.ParseUint(source.id, 10, 32)
		if err != nil || uid == 0 || source.validity == 0 || source.folder == "" || len(source.folder) > 1000 || strings.ContainsAny(source.folder, "\r\n\x00") {
			return errors.New("invalid source mailbox identity")
		}
	}
	if len(m.To)+len(m.CC)+len(m.BCC) == 0 && m.ReplyID == "" {
		return errors.New("at least one recipient is required")
	}
	if len(m.To)+len(m.CC)+len(m.BCC) > 100 || len(m.Subject) > 1000 || len(m.Body) > 1<<20 || strings.ContainsAny(m.Subject, "\r\n") {
		return errors.New("invalid message size or subject")
	}
	for _, list := range [][]string{m.To, m.CC, m.BCC} {
		for _, address := range list {
			if strings.ContainsAny(address, "\r\n") {
				return errors.New("invalid recipient")
			}
			if _, err := mail.ParseAddress(address); err != nil {
				return fmt.Errorf("invalid recipient: %w", err)
			}
		}
	}
	if m.SendAt.After(time.Now().AddDate(1, 0, 0)) {
		return errors.New("schedule must be within one year")
	}
	if len(m.TransactionID) > 100 {
		return errors.New("invalid transaction ID")
	}
	return nil
}
func (s *Service) Schedule(ctx context.Context, owner string, m Send) (Outbox, error) {
	return s.schedule(ctx, owner, m, "web")
}
func (s *Service) schedule(ctx context.Context, owner string, m Send, actor string) (Outbox, error) {
	if err := validateSend(m); err != nil {
		return Outbox{}, err
	}
	key := auth.Random()
	if m.TransactionID != "" {
		key = auth.Hash(owner + "\x00" + m.TransactionID)
	}
	address, err := s.Account(ctx, owner)
	if err != nil {
		return Outbox{}, err
	}
	state := s.owner(owner)
	state.write.Lock()
	defer state.write.Unlock()
	receipt, receiptErr := scanOutbox(s.pool.QueryRow(ctx, "SELECT "+outboxCols+" FROM mail_outbox WHERE id = $1 AND owner = $2", key, owner))
	if receiptErr == nil {
		if receipt.Account != address {
			return Outbox{}, errors.New("transaction belongs to a previously linked account")
		}
		return receipt, nil
	}
	if !errors.Is(receiptErr, pg.ErrNoRows) {
		return Outbox{}, receiptErr
	}
	if _, err := s.SenderIdentity(ctx, owner, m.From); err != nil {
		return Outbox{}, err
	}
	if m.SendAt.IsZero() {
		prefs, err := s.Preferences(ctx, owner)
		if err != nil {
			return Outbox{}, err
		}
		m.SendAt = time.Now().Add(time.Duration(prefs.UndoSeconds) * time.Second)
	}
	if m.SendAt.Before(time.Now()) {
		return Outbox{}, errors.New("send time must be in the future")
	}
	if err = s.checkRenamePending(ctx, owner, address); err != nil {
		return Outbox{}, err
	}
	if err = s.remapSendSources(ctx, owner, address, &m); err != nil {
		return Outbox{}, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return Outbox{}, err
	}
	if len(raw) > 15<<20 {
		return Outbox{}, errors.New("encoded message exceeds storage limit")
	}
	job := Outbox{ID: key, Owner: owner, Account: address, Payload: s.seal(raw), SendAt: m.SendAt, Created: time.Now(), Status: "pending", Actor: actor}
	_, err = s.pool.Exec(ctx, "INSERT INTO mail_outbox (id, owner, account, payload, send_at, created, status, actor) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING", job.ID, job.Owner, job.Account, job.Payload, job.SendAt, job.Created, job.Status, job.Actor)
	if err != nil {
		return Outbox{}, fmt.Errorf("schedule send: %w", err)
	}
	stored, err := scanOutbox(s.pool.QueryRow(ctx, "SELECT "+outboxCols+" FROM mail_outbox WHERE id = $1 AND owner = $2", key, owner))
	if err == nil && stored.Account != address {
		return Outbox{}, errors.New("transaction belongs to a previously linked account")
	}
	return stored, err
}
func (s *Service) Outbox(ctx context.Context, owner string) ([]Outbox, error) {
	account, err := s.Account(ctx, owner)
	if err != nil {
		return nil, err
	}
	jobs, err := s.queryOutbox(ctx, "SELECT "+outboxCols+" FROM mail_outbox WHERE owner = $1 AND account = $2 AND status NOT IN ('sent', 'cancelled', 'restored') ORDER BY created DESC LIMIT 100", owner, account)
	if err == nil {
		for i := range jobs {
			raw, openErr := s.open(jobs[i].Payload)
			if openErr != nil {
				return nil, openErr
			}
			var message Send
			if err = json.Unmarshal(raw, &message); err != nil {
				return nil, err
			}
			jobs[i].Message = &message
		}
	}
	return jobs, err
}

func (s *Service) OutboxMessage(ctx context.Context, owner, id string) (Send, error) {
	account, err := s.Account(ctx, owner)
	if err != nil {
		return Send{}, err
	}
	job, err := scanOutbox(s.pool.QueryRow(ctx, "SELECT "+outboxCols+" FROM mail_outbox WHERE id = $1 AND owner = $2 AND account = $3", id, owner, account))
	if err != nil {
		return Send{}, err
	}
	raw, err := s.open(job.Payload)
	if err != nil {
		return Send{}, err
	}
	var message Send
	err = json.Unmarshal(raw, &message)
	return message, err
}
func (s *Service) CancelSend(ctx context.Context, owner, id string) error {
	account, err := s.Account(ctx, owner)
	if err != nil {
		return err
	}
	result, err := s.pool.Exec(ctx, "UPDATE mail_outbox SET status = 'cancelled', payload_expires = $4 WHERE id = $1 AND owner = $2 AND account = $3 AND status = 'pending'", id, owner, account, time.Now().Add(14*24*time.Hour))
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return errors.New("send already started or is no longer pending")
	}
	return nil
}
func (s *Service) deliverNext(ctx context.Context) error {
	const due = "status = 'pending' AND send_at <= now() AND retry_at <= now()"
	job, err := scanOutbox(s.pool.QueryRow(ctx, "SELECT "+outboxCols+" FROM mail_outbox WHERE "+due+" ORDER BY send_at LIMIT 1"))
	if errors.Is(err, pg.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	work, release, allowed, err := s.jobWork(ctx, job.Owner, "mail_outbox", job.ID, "retry_at")
	if err != nil || !allowed {
		return err
	}
	defer release()
	ctx = work
	if job, err = scanOutbox(s.pool.QueryRow(ctx, "UPDATE mail_outbox SET status = 'sending' WHERE id = $1 AND "+due+" RETURNING "+outboxCols, job.ID)); errors.Is(err, pg.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	status, problem := "sent", ""
	if err = s.deliver(ctx, job); err != nil {
		var sentCopy *smtp.SentCopyError
		switch {
		case errors.Is(err, ErrRenamePending):
			status, problem = "pending", "Waiting for folder rename recovery."
		case errors.As(err, &sentCopy):
			problem = "Message sent; saving the Sent copy failed. Do not resend."
		default:
			status = "uncertain"
			problem = "Delivery could not be confirmed. Check Sent before retrying."
		}
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	var retryAt, expires *time.Time
	if status == "pending" {
		t := time.Now().Add(10 * time.Second)
		retryAt = &t
	}
	if status == "sent" {
		t := time.Now().Add(14 * 24 * time.Hour)
		expires = &t
	}
	_, updateErr := s.pool.Exec(finishCtx, "UPDATE mail_outbox SET status = $3, error = $4, retry_at = COALESCE($5, retry_at), payload_expires = COALESCE($6, payload_expires), payload = CASE WHEN $3 = 'sent' THEN NULL ELSE payload END WHERE id = $1 AND owner = $2", job.ID, job.Owner, status, problem, retryAt, expires)
	if updateErr != nil {
		return updateErr
	}
	if err != nil && !errors.Is(err, ErrRenamePending) {
		return fmt.Errorf("deliver outbox %s: %w", job.ID, err)
	}
	return nil
}
func (s *Service) deliver(ctx context.Context, job Outbox) error {
	connection, release, err := s.AcquireBulk(ctx, job.Owner)
	if err != nil {
		return err
	}
	defer release()
	if connection.Address != job.Account {
		return errors.New("the linked iCloud account changed before delivery")
	}
	if err := s.checkRenamePending(ctx, job.Owner, job.Account); err != nil {
		return errors.Join(ErrRenamePending, err)
	}
	// Reload after acquiring the command slot: rename recovery may have rewritten the payload.
	if job, err = scanOutbox(s.pool.QueryRow(ctx, "SELECT "+outboxCols+" FROM mail_outbox WHERE id = $1 AND owner = $2 AND account = $3", job.ID, job.Owner, job.Account)); err != nil {
		return err
	}
	raw, err := s.open(job.Payload)
	if err != nil {
		return err
	}
	var m Send
	if err = json.Unmarshal(raw, &m); err != nil {
		return err
	}
	from, err := s.SenderIdentity(ctx, job.Owner, m.From)
	if err != nil {
		return err
	}
	parsed, _ := mail.ParseAddress(from)
	connection.Sender.SetAliases([]string{parsed.Address})
	opts := smtp.SendOptions{CC: m.CC, BCC: m.BCC, HTML: m.HTML, Attachments: m.Attachments, From: from}
	if m.Automated {
		opts.Headers = map[string]string{"Auto-Submitted": "auto-generated"}
	}
	if m.ReplyID != "" {
		validity, validityErr := connection.Mail.UIDValidity(ctx, m.ReplyFolder)
		if validityErr != nil {
			return validityErr
		}
		if validity != m.ReplyValidity {
			return errors.New("reply mailbox changed before delivery")
		}
		original, originalErr := connection.Mail.GetEmail(ctx, m.ReplyFolder, m.ReplyID)
		if originalErr != nil {
			return originalErr
		}
		if original.MessageID != "" {
			if opts.Headers == nil {
				opts.Headers = map[string]string{}
			}
			opts.Headers["In-Reply-To"] = original.MessageID
			opts.Headers["References"] = strings.Join(append(append([]string(nil), original.References...), original.MessageID), " ")
		}
	}
	// The composer owns the envelope; the original message supplies only threading headers.
	err = connection.Sender.SendEmail(ctx, from, m.To, m.Subject, m.Body, opts)
	var sentCopy *smtp.SentCopyError
	if err != nil && !errors.As(err, &sentCopy) {
		return err
	}
	if m.DraftID != "" {
		validity, cleanupErr := connection.Mail.UIDValidity(ctx, m.DraftFolder)
		if cleanupErr == nil && validity != m.DraftValidity {
			cleanupErr = errors.New("draft mailbox changed; saved copy retained")
		}
		if cleanupErr == nil {
			cleanupErr = connection.Mail.DeleteEmail(ctx, m.DraftFolder, m.DraftID, true)
		}
		if cleanupErr != nil {
			err = errors.Join(err, &smtp.SentCopyError{Err: fmt.Errorf("remove sent draft: %w", cleanupErr)})
		}
	}
	release()
	refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	actor := job.Actor
	if actor == "" {
		actor = "web"
	}
	if refreshErr := s.Refresh(refreshCtx, job.Owner, actor, m.TransactionID); refreshErr != nil {
		err = errors.Join(err, &smtp.SentCopyError{Err: fmt.Errorf("refresh sent mirror: %w", refreshErr)})
	}
	return err
}

func (s *Service) RestoreUncertain(ctx context.Context, owner, id string) (Send, error) {
	account, err := s.Account(ctx, owner)
	if err != nil {
		return Send{}, err
	}
	state := s.owner(owner)
	state.write.Lock()
	defer state.write.Unlock()
	const where = "WHERE id = $1 AND owner = $2 AND account = $3 AND status IN ('uncertain', 'restored')"
	job, err := scanOutbox(s.pool.QueryRow(ctx, "SELECT "+outboxCols+" FROM mail_outbox "+where, id, owner, account))
	if err != nil {
		return Send{}, err
	}
	raw, err := s.open(job.Payload)
	if err != nil {
		return Send{}, err
	}
	var message Send
	if err = json.Unmarshal(raw, &message); err != nil {
		return Send{}, err
	}
	if _, err = s.pool.Exec(ctx, "UPDATE mail_outbox SET status = 'restored', payload_expires = $4 "+where, id, owner, account, time.Now().Add(14*24*time.Hour)); err != nil {
		return Send{}, err
	}
	message.TransactionID = ""
	message.SendAt = time.Time{}
	return message, nil
}
func (s *Service) cleanOutbox(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, sweepOutbox[0])
	return err
}
