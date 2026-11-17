package authhttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/olegpustovit/mcp-icloud-email/internal/components/auth"
)

func TestAccessFreshCallbackRecordsRefreshDenialAndRecovery(t *testing.T) {
	mux, s, p := identityMux(t, true)
	p.sub, p.email = "usr_eval_mail_access", "eval-access@olegpustovit.com"
	// A cryptographically valid identity does not create a binding/session when access is denied.
	p.accessMode.Store(1)
	denied := signIn(t, mux, "/")
	if denied.Code != 403 {
		t.Fatal("callback did not check fresh", denied.Code)
	}
	if _, err := s.Subject(t.Context(), p.email); !errors.Is(err, auth.ErrAccessDenied) {
		t.Fatal("denied callback linked an account")
	}
	p.accessMode.Store(0)
	accepted := signIn(t, mux, "/")
	if accepted.Code != 303 {
		t.Fatal("allowed callback failed", accepted.Code)
	}
	var cookie *http.Cookie
	for _, c := range accepted.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("callback did not create a session")
	}
	record, err := s.Get(t.Context(), cookie.Value, "session", false)
	if err != nil || record.Subject != p.sub {
		t.Fatal("session did not retain stable subject", err)
	}
	access, refresh := auth.Random(), auth.Random()
	client := auth.Random()
	for _, kind := range []string{"access", "refresh"} {
		secret := access
		if kind == "refresh" {
			secret = refresh
		}
		if err := s.Put(t.Context(), auth.Record{ID: auth.Hash(secret), Kind: kind, Email: p.email, Subject: p.sub, ClientID: client, Resource: s.Config.BaseURL + "/mcp", Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	token := func() *httptest.ResponseRecorder {
		body := url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {refresh}}.Encode()
		r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	me := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/me", nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if me().Code != 200 {
		t.Fatal("allowed session failed")
	}
	for _, state := range []int32{1, 2} {
		p.accessMode.Store(state)
		expected := 403
		if state == 2 {
			expected = 503
		}
		if w := token(); w.Code != expected {
			t.Fatal("refresh ignored central decision", w.Code)
		}
		if _, err := s.Get(t.Context(), refresh, "refresh", false); err != nil {
			t.Fatal("denial/outage consumed a valid refresh", err)
		}
		if w := me(); w.Code != expected {
			t.Fatal("existing session did not fail closed", w.Code)
		}
		r := httptest.NewRequest("POST", s.Config.BaseURL+"/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+access)
		if _, _, err := s.AuthenticateClient(r); err == nil {
			t.Fatal("independent MCP token bypassed central policy")
		}
	}
	p.accessMode.Store(0)
	if w := token(); w.Code != 200 {
		t.Fatal("restored refresh failed", w.Code)
	}
	if _, err := s.Get(t.Context(), refresh, "refresh", false); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("successful refresh did not consume old credential")
	}
	// Missing subjects are never inferred into old human credentials after enabling.
	legacy := auth.Random()
	if err := s.Put(t.Context(), auth.Record{ID: auth.Hash(legacy), Kind: "session", Email: p.email, Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/me", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: legacy})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("unbound old session admitted", w.Code)
	}
	// Logout must not be held behind the denied app lease.
	p.accessMode.Store(1)
	if err := s.CheckOwner(t.Context(), p.email, true); !errors.Is(err, auth.ErrAccessDenied) {
		t.Fatal("owner was not blocked")
	}
	if me().Code != 403 {
		t.Fatal("blocked cookie fixture still allowed")
	}
	r = httptest.NewRequest("POST", s.Config.BaseURL+"/api/auth/id/logout", nil)
	r.Header.Set("Origin", s.Config.BaseURL)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatal("denied session could not sign out", w.Code)
	}
	if p.accessChecks.Load() < 4 {
		t.Fatal("fixture did not call confidential endpoint")
	}
}
