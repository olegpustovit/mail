package mailsync

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olegpustovit/mail/imap"
	"github.com/olegpustovit/mail/smtp"
)

func deniedWork(ctx context.Context, _ string) (context.Context, context.CancelFunc, error) {
	next, cancel := context.WithCancel(ctx)
	cancel()
	return next, cancel, errors.New("owned access denied")
}
func TestAccessPausesEveryOwnerJobBeforeMutationOrAttemptConsumption(t *testing.T) {
	s := testMirror(t)
	s.cancel()
	s.wg.Wait()
	s.access = deniedWork
	cases := []struct {
		table, stateCol, state, field, insert string
		run                                   func(context.Context) error
	}{
		{"mail_outbox", "status", "pending", "retry_at", `INSERT INTO mail_outbox (id, owner, account, send_at, created, status) VALUES ($1, $2, $3, now() - interval '1 minute', now(), 'pending')`, s.deliverNext},
		{"mail_rule_jobs", "state", "pending", "next_attempt", `INSERT INTO mail_rule_jobs (id, owner, account, source_folder, source_uid, source_validity, source_key, state, created, next_attempt, attempts) VALUES ($1, $2, $3, '', '', 0, '', 'pending', now(), now() - interval '1 minute', 3)`, s.runRuleJob},
		{"mail_rule_applications", "state", "pending", "next_attempt", `INSERT INTO mail_rule_applications (id, owner, account, folder, validity, max_uid, state, created) VALUES ($1, $2, $3, '', 0, 0, 'pending', now())`, s.runRuleApplication},
		{"mail_folder_ops", "state", "pending", "next_attempt", `INSERT INTO mail_folder_ops (id, owner, account, transaction, from_name, to_name, state, next_attempt, created) VALUES ($1, $2, $3, '', '', '', 'pending', now() - interval '1 minute', now())`, s.runRename},
		{"mail_moves", "state", "snoozed", "next_attempt", `INSERT INTO mail_moves (id, owner, account, transaction, kind, from_folder, from_uid, from_validity, target, marker, state, next_attempt, created) VALUES ($1, $2, $3, '', 'move', '', '', 0, '', '', 'snoozed', now() - interval '1 minute', now())`, s.runMove},
	}
	for _, c := range cases {
		id := "eval-access-" + c.table
		if _, err := s.pool.Exec(t.Context(), c.insert, id, "eval-paused", "mirror@icloud.com"); err != nil {
			t.Fatal(c.table, err)
		}
		if err := c.run(t.Context()); err != nil {
			t.Fatal("paused dispatcher failed", c.table, err)
		}
		var state string
		var when time.Time
		if err := s.pool.QueryRow(t.Context(), "SELECT "+c.stateCol+", "+c.field+" FROM "+c.table+" WHERE id = $1", id).Scan(&state, &when); err != nil {
			t.Fatal(err)
		}
		if state != c.state {
			t.Fatal("access denial claimed/consumed a job", c.table)
		}
		if c.table == "mail_rule_jobs" {
			var attempts int
			if err := s.pool.QueryRow(t.Context(), "SELECT attempts FROM mail_rule_jobs WHERE id = $1", id).Scan(&attempts); err != nil || attempts != 3 {
				t.Fatal("access denial consumed an attempt", attempts, err)
			}
		}
		if !when.After(time.Now()) {
			t.Fatal("paused owner would starve the dispatch queue", c.table)
		}
	}
}

type accessSender struct{ calls atomic.Int32 }

func (s *accessSender) SetAliases([]string) {}
func (s *accessSender) SendEmail(context.Context, string, []string, string, string, smtp.SendOptions) error {
	s.calls.Add(1)
	return nil
}
func (s *accessSender) ReplyToEmail(context.Context, *imap.Email, string, bool, smtp.SendOptions) error {
	panic("unexpected reply")
}
func TestAccessPausedSendDoesNotStarveAnotherOwner(t *testing.T) {
	s := testMirror(t)
	s.cancel()
	s.wg.Wait()
	s.ctx, s.cancel = context.WithCancel(t.Context())
	s.dialSync = func(context.Context, string, string, func()) (syncTransport, error) {
		return &syncFake{mail: map[uint32]imap.Email{}, validity: 7, modseq: 1, next: 1, closed: make(chan struct{})}, nil
	}
	s.access = func(ctx context.Context, owner string) (context.Context, context.CancelFunc, error) {
		if owner == "eval-paused" {
			return deniedWork(ctx, owner)
		}
		next, cancel := context.WithCancel(ctx)
		return next, cancel, nil
	}
	sender := &accessSender{}
	s.dialCommand = func(context.Context, string, string) (*Connection, error) {
		return &Connection{Mail: laneTestClient{}, Sender: sender, Address: "mirror@icloud.com"}, nil
	}
	raw, _ := json.Marshal(Send{To: []string{"eval-target@example.test"}, Subject: "eval send", Body: "owned fixture"})
	for i, owner := range []string{"eval-paused", "eval-allowed"} {
		_, err := s.pool.Exec(t.Context(), `INSERT INTO mail_outbox (id, owner, account, status, send_at, created, payload) VALUES ($1, $1, 'mirror@icloud.com', 'pending', $2, now(), $3)`, owner, time.Now().Add(time.Duration(i-5)*time.Second), s.seal(raw))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.deliverNext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if sender.calls.Load() != 0 {
		t.Fatal("paused owner sent mail")
	}
	if err := s.deliverNext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if sender.calls.Load() != 1 {
		t.Fatal("paused head starved another eligible owner")
	}
	var status string
	if err := s.pool.QueryRow(t.Context(), `SELECT status FROM mail_outbox WHERE id = 'eval-paused'`).Scan(&status); err != nil || status != "pending" {
		t.Fatal("pause became an uncertain send", err)
	}
}

type abortableCommand struct {
	commandClient
	closed  atomic.Bool
	aborted chan struct{}
}

func (c *abortableCommand) Closed() bool { return c.closed.Load() }
func (c *abortableCommand) Close() error { return nil }
func (c *abortableCommand) Abort() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.aborted)
	}
	return nil
}
func TestAccessCancellationAbortsBorrowedCommandBeforeReleasingItsLane(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	wire := &abortableCommand{aborted: make(chan struct{})}
	s := &Service{ctx: t.Context(), sessions: map[string]map[commandLane]*session{}, credentials: func(context.Context, string) (string, string, error) { return "mirror@icloud.com", "owned", nil }, dialCommand: func(context.Context, string, string) (*Connection, error) { return &Connection{Mail: wire}, nil }}
	_, release, err := s.Acquire(ctx, "eval-owner")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-wire.aborted:
	case <-time.After(time.Second):
		t.Fatal("cancelled command stayed connected")
	}
	release()
	release()
	select {
	case s.sessions["eval-owner"][interactiveLane].gate <- struct{}{}:
		<-s.sessions["eval-owner"][interactiveLane].gate
	default:
		t.Fatal("cancelled command retained its lane")
	}
}

func TestAccessPausesPushAndPrefetchBeforeOwnerDataOrNetwork(t *testing.T) {
	// A nil database/client deliberately makes any downstream work fail loudly.
	// A paused human keeps their subscription and downloaded-body state intact.
	s := &Service{access: deniedWork}
	err := s.pushDevice(t.Context(), PushDevice{Owner: "eval-paused"}, func(context.Context, string, string) (bool, error) {
		t.Fatal("paused push resolved a session")
		return true, nil
	}, "", nil)
	if !errors.Is(err, ErrAccessPaused) {
		t.Fatal("push did not pause", err)
	}
	if err = s.prefetchBodies(t.Context(), prefetchRequest{owner: "eval-paused"}); !errors.Is(err, ErrAccessPaused) {
		t.Fatal("prefetch did not pause", err)
	}
}
