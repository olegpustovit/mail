package mailsync

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olegpustovit/mail/imap"
	"github.com/olegpustovit/mail/internal/components/auth"
	"github.com/olegpustovit/mail/smtp"
)

type idleAccessWire struct{ *syncFake }

func (idleAccessWire) CanIdle() bool                    { return true }
func (idleAccessWire) StartIdle() (func() error, error) { return func() error { return nil }, nil }

type interruptedAccessSender struct{ started chan struct{} }

func (*interruptedAccessSender) SetAliases([]string) {}
func (s *interruptedAccessSender) SendEmail(ctx context.Context, _ string, _ []string, _, _ string, _ smtp.SendOptions) error {
	close(s.started)
	<-ctx.Done()
	return ctx.Err()
}
func (*interruptedAccessSender) ReplyToEmail(context.Context, *imap.Email, string, bool, smtp.SendOptions) error {
	panic("unexpected reply")
}

// This deliberately uses the production timer intervals, real Mongo storage and
// the published access SDK. The policy endpoint and mail transports are owned
// fakes: no external ID grant, mailbox or SMTP recipient is touched.
func TestAccessActiveWorkRehearsal(t *testing.T) {
	if os.Getenv("MAIL_ACCESS_REHEARSAL") != "1" {
		t.Skip("set MAIL_ACCESS_REHEARSAL=1 for the timed active-work rehearsal")
	}
	const owner = "eval-access-rehearsal@olegpustovit.com"
	const subject = "usr_eval_mail_rehearsal"
	var mode atomic.Int32
	var policyChecks atomic.Int64
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if r.URL.Path != "/api/access/check" || !ok || id != "app_eval_mail" || secret != "eval-owned-secret" {
			http.Error(w, "invalid client", 401)
			return
		}
		var input struct {
			UserID string `json:"user_id"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.UserID != subject {
			http.Error(w, "invalid subject", 422)
			return
		}
		policyChecks.Add(1)
		state := mode.Load()
		if state == 2 {
			http.Error(w, "owned policy unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		reason := "group_grant"
		if state == 1 {
			reason = "user_block"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": id, "subject": subject, "allowed": state == 0, "reason_code": reason, "policy_revision": 1, "lease_seconds": 60})
	}))
	defer provider.Close()
	s := testMirror(t)
	s.cancel()
	s.wg.Wait()
	s.ctx, s.cancel = context.WithCancel(t.Context())
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	var schema string
	if err := s.pool.QueryRow(t.Context(), "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(t.Context(), auth.Config{BaseURL: "https://mail.example.test", PostgresURI: os.Getenv("MAIL_TEST_POSTGRES_URI"), Schema: schema, EncryptionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	if _, err = a.LinkIdentity(t.Context(), subject, owner); err != nil {
		t.Fatal(err)
	}
	if err = a.SaveAccount(t.Context(), owner, "eval@icloud.com", "owned-fixture-password"); err != nil {
		t.Fatal(err)
	}
	if err = a.EnableAccess(auth.IdentityConfig{Issuer: provider.URL, ClientID: "app_eval_mail", ClientSecret: "eval-owned-secret", AccessEnabled: true}); err != nil {
		t.Fatal(err)
	}
	s.access, s.credentials = a.WatchAccess, a.Credentials
	token := auth.Random()
	if err = a.Put(t.Context(), auth.Record{ID: auth.Hash(token), Kind: "access", Email: owner, Subject: subject, ClientID: "eval_mcp", Resource: a.Config.BaseURL + "/mcp", Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// Exercise the same authenticate + watched context sequence as the HTTP/MCP
	// guard while all of the active owner work below remains open.
	protected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _, err := a.AuthenticateClient(r)
		if err == nil {
			var release context.CancelFunc
			_, release, err = a.WatchAccess(r.Context(), who)
			if release != nil {
				defer release()
			}
		}
		status := 200
		if errors.Is(err, auth.ErrAccessDenied) {
			status = 403
		} else if errors.Is(err, auth.ErrAccessUnavailable) {
			status = 503
		} else if err != nil {
			status = 401
		}
		w.WriteHeader(status)
	}))
	defer protected.Close()
	var load sync.WaitGroup
	loadCtx, stopLoad := context.WithCancel(t.Context())
	var responses [600]atomic.Int64
	for range 4 {
		load.Go(func() {
			client := &http.Client{Timeout: 2 * time.Second}
			for loadCtx.Err() == nil {
				r, _ := http.NewRequestWithContext(loadCtx, "POST", protected.URL, nil)
				r.Header.Set("Authorization", "Bearer "+token)
				resp, err := client.Do(r)
				if err != nil {
					if loadCtx.Err() == nil {
						responses[0].Add(1)
					}
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode < len(responses) {
					responses[resp.StatusCode].Add(1)
				}
				select {
				case <-time.After(100 * time.Millisecond):
				case <-loadCtx.Done():
					return
				}
			}
		})
	}
	defer func() { stopLoad(); load.Wait() }()
	measurements := map[string]any{"scope": "Owned Mongo + published SDK; simulated policy endpoint and mail transports; no production or actual provider claim", "workers": 4, "interval_ms": 100, "active_recheck_seconds": 25, "per_check_timeout_seconds": 2, "maximum_removal_ms": 60000}
	for _, phase := range []struct {
		name  string
		mode  int32
		cause error
	}{{"removal", 1, auth.ErrAccessDenied}, {"policy_unavailable", 2, auth.ErrAccessUnavailable}} {
		mode.Store(0)
		wire := &syncFake{mail: map[uint32]imap.Email{}, validity: 7, modseq: 1, next: 1, closed: make(chan struct{})}
		s.dialSync = func(context.Context, string, string, func()) (syncTransport, error) { return idleAccessWire{wire}, nil }
		command := &abortableCommand{aborted: make(chan struct{})}
		sender := &interruptedAccessSender{started: make(chan struct{})}
		s.dialCommand = func(context.Context, string, string) (*Connection, error) {
			return &Connection{Mail: command, Sender: sender, Address: "eval@icloud.com"}, nil
		}
		m, err := s.Start(t.Context(), owner)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-m.ready:
		case <-time.After(5 * time.Second):
			t.Fatal("monitor not ready")
		}
		idle, releaseIdle, err := a.WatchAccess(t.Context(), owner)
		if err != nil {
			t.Fatal(err)
		}
		borrowCtx, releaseWatch, err := a.WatchAccess(t.Context(), owner)
		if err != nil {
			t.Fatal(err)
		}
		_, releaseCommand, err := s.Acquire(borrowCtx, owner)
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(Send{To: []string{"eval-target@example.test"}, Subject: "eval interrupted send", Body: "owned fixture"})
		id := "eval-" + phase.name
		if _, err = s.pool.Exec(t.Context(), `INSERT INTO mail_outbox (id, owner, account, status, send_at, created, payload) VALUES ($1, $2, 'eval@icloud.com', 'pending', now() - interval '1 minute', now(), $3)`, id, owner, s.seal(payload)); err != nil {
			t.Fatal(err)
		}
		delivered := make(chan error, 1)
		go func() { delivered <- s.deliverNext(t.Context()) }()
		select {
		case <-sender.started:
		case <-time.After(5 * time.Second):
			t.Fatal("owned SMTP did not start")
		}
		start := time.Now()
		mode.Store(phase.mode)
		deadline, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		wait := func(label string, done <-chan struct{}) {
			t.Helper()
			select {
			case <-done:
			case <-deadline.Done():
				t.Fatal(label, "exceeded the revocation bound")
			}
		}
		wait("idle owner context", idle.Done())
		wait("idle IMAP connection", wire.closed)
		wait("monitor", m.done)
		wait("borrowed raw command", command.aborted)
		select {
		case err = <-delivered:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("interrupted send did not propagate cancellation", err)
			}
		case <-deadline.Done():
			t.Fatal("active SMTP exceeded the revocation bound")
		}
		cancel()
		if !errors.Is(context.Cause(idle), phase.cause) {
			t.Fatal("wrong cancellation cause", context.Cause(idle))
		}
		measurements[phase.name+"_ms"] = time.Since(start).Milliseconds()
		releaseCommand()
		releaseWatch()
		releaseIdle()
		var status string
		if err = s.pool.QueryRow(t.Context(), `SELECT status FROM mail_outbox WHERE id = $1`, id).Scan(&status); err != nil || status != "uncertain" {
			t.Fatal("ambiguous SMTP was not retained for review", err)
		}
		// New work must fail immediately even with the original unexpired token.
		if _, err = s.Start(t.Context(), owner); !errors.Is(err, phase.cause) {
			t.Fatal("new monitor bypassed current policy", err)
		}
	}
	mode.Store(0)
	if err = a.CheckOwner(t.Context(), owner, true); err != nil {
		t.Fatal("restoration failed", err)
	}
	m, err := s.Start(t.Context(), owner)
	if err != nil {
		t.Fatal("monitor did not restart after restoration", err)
	}
	m.cancel()
	select {
	case <-m.done:
	case <-time.After(time.Second):
		t.Fatal("restored monitor did not clean up")
	}
	stopLoad()
	load.Wait()
	if responses[0].Load() != 0 || responses[401].Load() != 0 {
		t.Fatal("protected load had transport/authentication errors")
	}
	for status := range responses {
		if status != 0 && status != 200 && status != 403 && status != 503 && responses[status].Load() != 0 {
			t.Fatal("unexpected protected response", status)
		}
	}
	if responses[403].Load() == 0 || responses[503].Load() == 0 {
		t.Fatal("load did not observe both failure modes")
	}
	measurements["responses"] = map[string]int64{"allowed": responses[200].Load(), "denied": responses[403].Load(), "unavailable": responses[503].Load()}
	measurements["policy_checks"] = policyChecks.Load()
	measurements["restoration"] = "pass"
	measurements["ambiguous_send_retained"] = true
	if target := os.Getenv("MAIL_ACCESS_REHEARSAL_REPORT"); target != "" {
		data, err := json.MarshalIndent(measurements, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(target, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(fmt.Sprint(measurements))
}
