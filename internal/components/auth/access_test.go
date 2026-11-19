package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/olegpustovit/mail/internal/pg/pgtest"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestAccessWatcherStopsIdleAndBlockedChecksAtProductionDeadlines(t *testing.T) {
	for _, failure := range []error{ErrAccessDenied, ErrAccessUnavailable} {
		synctest.Test(t, func(t *testing.T) {
			var revoked atomic.Bool
			var freshCalls atomic.Int32
			start := time.Now()
			ctx, cancel, err := watchChecks(t.Context(), func(ctx context.Context, fresh bool) error {
				if fresh {
					freshCalls.Add(1)
				}
				if revoked.Load() {
					return failure
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			synctest.Wait()
			revoked.Store(true)
			time.Sleep(24 * time.Second)
			if ctx.Err() != nil {
				t.Fatal("lease ended before its fresh check")
			}
			time.Sleep(time.Second)
			synctest.Wait()
			if !errors.Is(context.Cause(ctx), failure) || freshCalls.Load() != 2 || time.Since(start) != 25*time.Second {
				t.Fatal("idle work exceeded its actual 25-second check")
			}
		})
	}
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		ctx, cancel, err := watchChecks(t.Context(), func(ctx context.Context, fresh bool) error {
			if calls.Add(1) > 1 {
				<-ctx.Done()
				return ErrAccessUnavailable
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cancel()
		time.Sleep(27 * time.Second)
		synctest.Wait()
		if !errors.Is(context.Cause(ctx), ErrAccessUnavailable) {
			t.Fatal("outage exceeded 27 seconds")
		}
	})
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		_, cancel, err := watchChecks(t.Context(), func(context.Context, bool) error { calls.Add(1); return nil })
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		synctest.Wait()
		time.Sleep(time.Minute)
		if calls.Load() != 1 {
			t.Fatal("released operation continued checking")
		}
	})
}
func TestAccessRecordsRequireStableBindingAndProtectCredentials(t *testing.T) {
	uri, schema := pgtest.New(t)
	ctx := t.Context()
	s, err := New(ctx, Config{BaseURL: "https://mail.example.test", PostgresURI: uri, Schema: schema, EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	const owner = "eval-access@olegpustovit.com"
	const sub = "usr_eval_mail"
	if _, err = s.LinkIdentity(ctx, sub, owner); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveAccount(ctx, owner, "eval@icloud.com", "owned-fixture-password"); err != nil {
		t.Fatal(err)
	}
	var mode atomic.Int32
	s.access = func(_ context.Context, subject string, _ bool) error {
		if subject != sub {
			t.Error("wrong stored subject")
		}
		switch mode.Load() {
		case 1:
			return ErrAccessDenied
		case 2:
			return ErrAccessUnavailable
		}
		return nil
	}
	credential := Random()
	record := Record{ID: Hash(credential), Kind: "access", Email: owner, Subject: sub, ClientID: "eval-client", Resource: s.Config.BaseURL + "/mcp", Expires: time.Now().Add(time.Hour)}
	if err = s.Put(ctx, record); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", s.Config.BaseURL+"/mcp", nil)
	request.Header.Set("Authorization", "Bearer "+credential)
	if _, _, err = s.AuthenticateClient(request); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []Record{{Email: owner}, {Email: owner, Subject: "usr_foreign"}, {Email: "unbound@olegpustovit.com", Subject: sub}} {
		if err = s.CheckRecord(ctx, changed, false); !errors.Is(err, ErrAccessDenied) {
			t.Fatal("missing/foreign binding allowed")
		}
	}
	for _, state := range []int32{1, 2} {
		mode.Store(state)
		expected := ErrAccessDenied
		if state == 2 {
			expected = ErrAccessUnavailable
		}
		if _, _, err = s.AuthenticateClient(request); !errors.Is(err, expected) {
			t.Fatal("existing bearer bypassed current eligibility", err)
		}
		if _, _, err = s.Credentials(ctx, owner); !errors.Is(err, expected) {
			t.Fatal("decrypted credentials bypassed current eligibility", err)
		}
	}
	mode.Store(0)
	// Verified email changes cannot move an existing subject to another mailbox.
	if linked, err := s.LinkIdentity(ctx, sub, "changed@olegpustovit.com"); err != nil || linked != owner {
		t.Fatal("binding moved on email change", err)
	}
	if err = s.CheckRecord(ctx, record, true); err != nil {
		t.Fatal(err)
	}
	work, cancel, err := s.WatchAccess(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-work.Done():
	case <-time.After(time.Second):
		t.Fatal("work context not released")
	}
}

func TestWatchedWorkMustStartWithAFreshDecision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel, err := watchChecks(t.Context(), func(_ context.Context, fresh bool) error {
			if !fresh {
				return nil
			}
			return ErrAccessDenied
		})
		defer cancel()
		if !errors.Is(err, ErrAccessDenied) || ctx.Err() == nil {
			t.Fatal("near-expired cached allow started a new long operation")
		}
	})
}
