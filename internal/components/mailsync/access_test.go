package mailsync

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olegpustovit/mcp-icloud-email/imap"
	"github.com/olegpustovit/mcp-icloud-email/smtp"
	"go.mongodb.org/mongo-driver/v2/bson"
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
		collection, field string
		seed              bson.M
		run               func(context.Context) error
	}{
		{"mail_outbox", "retry_at", bson.M{"status": "pending", "send_at": time.Now().Add(-time.Minute)}, s.deliverNext},
		{"mail_rule_jobs", "next_attempt", bson.M{"state": "pending", "next_attempt": time.Now().Add(-time.Minute), "attempts": int32(3), "created": time.Now()}, s.runRuleJob},
		{"mail_rule_applications", "next_attempt", bson.M{"state": "pending", "created": time.Now()}, s.runRuleApplication},
		{"mail_folder_ops", "next_attempt", bson.M{"state": "pending", "next_attempt": time.Now().Add(-time.Minute), "created": time.Now()}, s.runRename},
		{"mail_moves", "next_attempt", bson.M{"state": "snoozed", "next_attempt": time.Now().Add(-time.Minute)}, s.runMove},
	}
	for _, c := range cases {
		id := "eval-access-" + c.collection
		c.seed["_id"] = id
		c.seed["owner"] = "eval-paused"
		c.seed["account"] = "mirror@icloud.com"
		if _, err := s.db.Collection(c.collection).InsertOne(t.Context(), c.seed); err != nil {
			t.Fatal(err)
		}
		if err := c.run(t.Context()); err != nil {
			t.Fatal("paused dispatcher failed", c.collection, err)
		}
		var actual bson.M
		if err := s.db.Collection(c.collection).FindOne(t.Context(), bson.M{"_id": id}).Decode(&actual); err != nil {
			t.Fatal(err)
		}
		if actual["status"] != c.seed["status"] || actual["state"] != c.seed["state"] || actual["attempts"] != c.seed["attempts"] {
			t.Fatal("access denial claimed/consumed a job", c.collection)
		}
		if when, ok := actual[c.field].(bson.DateTime); !ok || !when.Time().After(time.Now()) {
			t.Fatal("paused owner would starve the dispatch queue", c.collection)
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
		_, err := s.db.Collection("mail_outbox").InsertOne(t.Context(), bson.M{"_id": owner, "owner": owner, "account": "mirror@icloud.com", "status": "pending", "send_at": time.Now().Add(time.Duration(i-5) * time.Second), "payload": s.seal(raw)})
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
	var first Outbox
	if err := s.db.Collection("mail_outbox").FindOne(t.Context(), bson.M{"_id": "eval-paused"}).Decode(&first); err != nil || first.Status != "pending" {
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
