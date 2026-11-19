package authhttp

import (
	"context"
	"encoding/json"
	"github.com/olegpustovit/mail/internal/components/auth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRedirectValidation(t *testing.T) {
	for _, v := range []struct {
		uri  string
		want bool
	}{{"https://chatgpt.com/connector_platform/oauth/callback", true}, {"http://localhost:123/cb", true}, {"https://evil.com/#fragment", false}, {"https://user:pass@example.com/cb", false}, {"http://example.com/cb", false}, {"javascript:alert(1)", false}, {"//evil.com", false}} {
		if validRedirect(v.uri) != v.want {
			t.Errorf("redirect %s", v.uri)
		}
	}
}
func TestUnauthorizedAndOrigin(t *testing.T) {
	h := New(&auth.Service{Config: auth.Config{BaseURL: "https://mail.example.com"}})
	mux := http.NewServeMux()
	h.Register(mux)
	for _, tc := range []struct {
		method, path string
		want         int
	}{{"GET", "/api/me", 401}, {"PUT", "/api/account", 403}, {"POST", "/auth/logout", 403}, {"POST", "/auth/resend", 403}, {"GET", "/.well-known/oauth-protected-resource/mcp", 200}} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Errorf("%s: %d", tc.path, w.Code)
		}
	}
}

func TestAccountPersistencePrecedesSyncInvalidation(t *testing.T) {
	ctx := context.Background()
	s := testService(t)
	var err error
	owner := "link-order-" + strings.ToLower(auth.Random()) + "@olegpustovit.com"
	session := auth.Random()
	if err = s.Put(ctx, auth.Record{ID: auth.Hash(session), Kind: "session", Email: owner, Expires: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	defer s.Delete(ctx, session)
	defer s.DeleteAccount(ctx, owner)
	h := New(s)
	h.ValidateAccount = func(context.Context, string, string, string) error { return nil }
	checked := 0
	h.InvalidateAccount = func(ctx context.Context, email string, disconnect bool) error {
		checked++
		account, err := s.Account(ctx, email)
		if err != nil {
			return err
		}
		if disconnect && len(account.Secret) != 0 {
			t.Fatal("unlink invalidated sync before deleting credentials")
		}
		if !disconnect && account.ICloudEmail != "new@icloud.com" {
			t.Fatal("replace invalidated sync before saving new credentials")
		}
		return nil
	}
	mux := http.NewServeMux()
	h.Register(mux)
	for _, method := range []string{"PUT", "DELETE"} {
		body := `{"email":"new@icloud.com","password":"app-specific-password"}`
		if method == "DELETE" {
			body = ""
		}
		r := httptest.NewRequest(method, "/api/account", strings.NewReader(body))
		r.Header.Set("Origin", "https://mail.example.com")
		r.AddCookie(&http.Cookie{Name: "__Host-mail_session", Value: session})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatalf("%s: %d %s", method, w.Code, w.Body.String())
		}
	}
	if checked != 2 {
		t.Fatal("credential changes did not invalidate synchronization")
	}
}
func TestOAuthPKCEIntegration(t *testing.T) {
	ctx := context.Background()
	s := testService(t)
	var e error
	h := New(s)
	mux := http.NewServeMux()
	h.Register(mux)
	request := func(path string, values url.Values) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		mux.ServeHTTP(w, r)
		return w
	}
	// Exercise registration and explicit browser consent before token exchange.
	registrationBody := `{"redirect_uris":["https://client.example.com/cb"],"client_name":"Test client","token_endpoint_auth_method":"none","client_uri":"https://client.example.com","contacts":["support@client.example.com"],"custom_metadata":"ignored"}`
	rw := httptest.NewRecorder()
	mux.ServeHTTP(rw, httptest.NewRequest("POST", "/oauth/register", strings.NewReader(registrationBody)))
	if rw.Code != 201 {
		t.Fatal("registration failed", rw.Body.String())
	}
	var registered struct {
		ID string `json:"client_id"`
	}
	_ = json.Unmarshal(rw.Body.Bytes(), &registered)
	defer s.Delete(ctx, registered.ID)
	browserSession := auth.Random()
	if e = s.Put(ctx, auth.Record{ID: auth.Hash(browserSession), Kind: "session", Email: "ursus95@gmail.com", Expires: time.Now().Add(time.Minute)}); e != nil {
		t.Fatal(e)
	}
	defer s.Delete(ctx, browserSession)
	browserVerifier := auth.Random()
	query := url.Values{"client_id": {registered.ID}, "redirect_uri": {"https://client.example.com/cb"}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {auth.Hash(browserVerifier)}, "state": {"client-state"}}
	path := "/oauth/authorize?" + query.Encode()
	getConsent := httptest.NewRequest("GET", path, nil)
	getConsent.AddCookie(&http.Cookie{Name: "__Host-mail_session", Value: browserSession})
	rw = httptest.NewRecorder()
	mux.ServeHTTP(rw, getConsent)
	if rw.Code != 200 {
		t.Fatal("consent page failed", rw.Code, rw.Body.String())
	}
	for header, want := range map[string]string{
		"Referrer-Policy":         "same-origin",
		"Cache-Control":           "no-store, no-transform",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://client.example.com; frame-ancestors 'none'; base-uri 'none'",
	} {
		if got := rw.Header().Get(header); got != want {
			t.Errorf("consent %s = %q, want %q", header, got, want)
		}
	}
	match := regexp.MustCompile(`name="consent" value="([^"]+)"`).FindStringSubmatch(rw.Body.String())
	if len(match) != 2 {
		t.Fatal("missing consent nonce")
	}
	form := url.Values{"consent": {match[1]}, "decision": {"allow"}}
	for _, origin := range []string{"", "null", "https://evil.example"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.AddCookie(&http.Cookie{Name: "__Host-mail_session", Value: browserSession})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("consent accepted origin %q: %d", origin, w.Code)
		}
	}
	postConsent := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	postConsent.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postConsent.Header.Set("Origin", "https://mail.example.com")
	postConsent.AddCookie(&http.Cookie{Name: "__Host-mail_session", Value: browserSession})
	rw = httptest.NewRecorder()
	mux.ServeHTTP(rw, postConsent)
	if rw.Code != 303 {
		t.Fatal("consent failed", rw.Code, rw.Body.String())
	}
	location, _ := url.Parse(rw.Header().Get("Location"))
	if location.Query().Get("state") != "client-state" || location.Query().Get("code") == "" {
		t.Fatal("bad authorization response")
	}
	defer s.Delete(ctx, location.Query().Get("code"))
	verifier := auth.Random()
	clientID := auth.Random()
	newCode := func() string {
		code := auth.Random()
		e = s.Put(ctx, auth.Record{ID: auth.Hash(code), Kind: "code", Email: "ursus95@gmail.com", ClientID: clientID, Redirect: "https://client.example.com/cb", Challenge: auth.Hash(verifier), Resource: "https://mail.example.com/mcp", Expires: time.Now().Add(time.Minute)})
		if e != nil {
			t.Fatal(e)
		}
		return code
	}
	values := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {"https://client.example.com/cb"}, "code_verifier": {verifier}, "code": {newCode()}}
	bad := url.Values{}
	for k, v := range values {
		bad[k] = append([]string(nil), v...)
	}
	bad.Set("code_verifier", auth.Random())
	if w := request("/oauth/token", bad); w.Code != 400 {
		t.Fatal("bad PKCE accepted")
	}
	values.Set("code", newCode())
	w := request("/oauth/token", values)
	if w.Code != 200 {
		t.Fatalf("exchange %d %s", w.Code, w.Body.String())
	}
	var tokens struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if json.Unmarshal(w.Body.Bytes(), &tokens) != nil || tokens.Access == "" || tokens.Refresh == "" {
		t.Fatal("missing tokens")
	}
	defer s.Revoke(ctx, tokens.Access)
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+tokens.Access)
	if email, e := s.Authenticate(r); e != nil || email != "ursus95@gmail.com" {
		t.Fatal("bearer rejected", e)
	}
	if w = request("/oauth/token", values); w.Code != 400 {
		t.Fatal("code replay accepted")
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tokens.Refresh}}
	if w = request("/oauth/token", refresh); w.Code != 200 {
		t.Fatal("refresh failed")
	}
	if w = request("/oauth/token", refresh); w.Code != 400 {
		t.Fatal("refresh replay accepted")
	}
	if e = s.Revoke(ctx, tokens.Access); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(r); e == nil {
		t.Fatal("revocation failed")
	}
}
func TestMetadataAliasAndCORS(t *testing.T) {
	h := New(&auth.Service{Config: auth.Config{BaseURL: "https://mail.example.com"}})
	mux := http.NewServeMux()
	h.Register(mux)
	var root string
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("metadata %s: %d", path, w.Code)
		}
		if root == "" {
			root = w.Body.String()
		} else if w.Body.String() != root {
			t.Fatal("metadata alias differs")
		}
	}
	for _, path := range []string{"/.well-known/oauth-authorization-server/mcp", "/.well-known/oauth-protected-resource/mcp", "/oauth/register", "/oauth/token", "/oauth/revoke"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("OPTIONS", path, nil)
		r.Header.Set("Origin", "https://grok.com")
		r.Header.Set("Access-Control-Request-Method", "POST")
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Headers") == "" {
			t.Fatalf("preflight %s: %d", path, w.Code)
		}
	}
}

func TestConsentEscapesClientMetadata(t *testing.T) {
	var output strings.Builder
	if err := consent.Execute(&output, struct{ Name, Email, Token string }{
		`<script>alert("client")</script>`, "user@olegpustovit.com", `" autofocus onfocus="alert(1)`,
	}); err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if strings.Contains(html, "<script>") || strings.Contains(html, `value="" autofocus`) {
		t.Fatal("untrusted metadata was rendered as HTML")
	}
	if !strings.Contains(html, "user@olegpustovit.com") || !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("missing escaped account or client identity")
	}
}
