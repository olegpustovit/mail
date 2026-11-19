package authhttp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olegpustovit/mail/internal/components/auth"
)

// provider is a minimal Microapps ID that signs real RS256 tokens for a configurable verified identity.
type provider struct {
	mu            sync.Mutex
	key           *rsa.PrivateKey
	codes         map[string]url.Values
	sub, email    string
	emailVerified bool
	accessMode    atomic.Int32
	accessChecks  atomic.Int32
}

func (p *provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	issuer := "http://" + r.Host
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/access/check":
		p.accessChecks.Add(1)
		id, secret, ok := r.BasicAuth()
		if !ok || id != "app_mail" || secret != "eval-confidential-secret" {
			http.Error(w, "invalid client", 401)
			return
		}
		if p.accessMode.Load() == 2 {
			http.Error(w, "unavailable", 503)
			return
		}
		var input struct {
			UserID string `json:"user_id"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			http.Error(w, "invalid", 422)
			return
		}
		allowed := p.accessMode.Load() == 0
		reason := "group_grant"
		if !allowed {
			reason = "user_block"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "app_mail", "subject": input.UserID, "allowed": allowed, "reason_code": reason, "policy_revision": 1, "lease_seconds": 60})
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/jwks":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "k", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()), "e": "AQAB"}}})
	case "/authorize":
		code := auth.Random()
		p.codes[code] = r.URL.Query()
		callback, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
		callback.RawQuery = url.Values{"code": {code}, "state": {r.URL.Query().Get("state")}}.Encode()
		http.Redirect(w, r, callback.String(), http.StatusSeeOther)
	case "/token":
		_ = r.ParseForm()
		q, ok := p.codes[r.Form.Get("code")]
		if !ok {
			http.Error(w, "invalid grant", 400)
			return
		}
		claims, _ := json.Marshal(map[string]any{"iss": issuer, "aud": "app_mail", "sub": p.sub, "email": p.email, "email_verified": p.emailVerified, "nonce": q.Get("nonce"), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()})
		input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(input))
		signature, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "token_type": "Bearer", "expires_in": 60, "id_token": input + "." + base64.RawURLEncoding.EncodeToString(signature)})
	default:
		http.NotFound(w, r)
	}
}

func identityMux(t *testing.T, enforced ...bool) (*http.ServeMux, *auth.Service, *provider) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{key: key, codes: map[string]url.Values{}, emailVerified: true}
	server := httptest.NewServer(p)
	t.Cleanup(server.Close)
	s := testService(t)
	h := New(s)
	cfg := auth.IdentityConfig{Issuer: server.URL, ClientID: "app_mail", CookieKey: [32]byte{7}}
	if len(enforced) > 0 && enforced[0] {
		cfg.AccessEnabled = true
		cfg.ClientSecret = "eval-confidential-secret"
	}
	if err = h.EnableIdentity(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return mux, s, p
}

// signIn runs login, the provider's authorize redirect and the callback, returning the callback response.
func signIn(t *testing.T, mux *http.ServeMux, returnTo string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "https://mail.example.com/api/auth/id/login?return_to="+url.QueryEscape(returnTo), nil))
	if w.Code != 303 {
		t.Fatal("login did not redirect", w.Code, w.Body.String())
	}
	flow := w.Result().Cookies()[0]
	if flow.Name != "__Host-idclient-flow" {
		t.Fatal("missing flow cookie")
	}
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Get(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	callback, _ := url.Parse(res.Header.Get("Location"))
	r := httptest.NewRequest("GET", callback.RequestURI(), nil)
	r.AddCookie(flow)
	out := httptest.NewRecorder()
	mux.ServeHTTP(out, r)
	return out
}

func TestMicroappsIDSignInSessionAndLogout(t *testing.T) {
	mux, _, p := identityMux(t)
	p.sub, p.email = "sub-person", "Person@OlegPustovit.com"
	w := signIn(t, mux, "/oauth/authorize?client_id=x")
	if w.Code != 303 || w.Header().Get("Location") != "/oauth/authorize?client_id=x" {
		t.Fatal("callback did not return to the OAuth request", w.Code, w.Header().Get("Location"))
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-mail_session" {
			session = c
		}
	}
	if session == nil || !session.Secure || !session.HttpOnly || session.Path != "/" || session.Domain != "" {
		t.Fatal("missing or unsafe __Host- session cookie")
	}
	me := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/me", nil)
		r.AddCookie(session)
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, r)
		return out
	}
	if out := me(); out.Code != 200 || !strings.Contains(out.Body.String(), `"email":"person@olegpustovit.com"`) {
		t.Fatal("session did not identify the linked owner", out.Code, out.Body.String())
	}
	// Logout needs the exact origin, then revokes the session server-side.
	logout := func(origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://mail.example.com/api/auth/id/logout", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r.AddCookie(session)
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, r)
		return out
	}
	if out := logout("https://evil.example"); out.Code != 403 || me().Code != 200 {
		t.Fatal("cross-origin logout accepted", out.Code)
	}
	if out := logout("https://mail.example.com"); out.Code != 303 || me().Code != 401 {
		t.Fatal("logout did not revoke the session", out.Code)
	}
}

func TestMicroappsIDDeniesUnlistedAndUnverified(t *testing.T) {
	mux, _, p := identityMux(t)
	p.sub, p.email = "sub-stranger", "stranger@example.com"
	if w := signIn(t, mux, "/"); w.Code != 403 || len(w.Result().Cookies()) != 1 {
		t.Fatal("unlisted email signed in", w.Code)
	}
	p.sub, p.email, p.emailVerified = "sub-unverified", "person@olegpustovit.com", false
	if w := signIn(t, mux, "/"); w.Code != 403 {
		t.Fatal("unverified email signed in", w.Code)
	}
	p.sub, p.email, p.emailVerified = "sub-a", "owner@olegpustovit.com", true
	if w := signIn(t, mux, "/"); w.Code != 303 {
		t.Fatal("first subject denied", w.Code)
	}
	p.sub = "sub-b"
	if w := signIn(t, mux, "/"); w.Code != 403 {
		t.Fatal("second subject took over a linked owner", w.Code)
	}
}

func TestOAuthAuthorizeRequiresMicroappsID(t *testing.T) {
	mux, _, _ := identityMux(t)
	body := `{"redirect_uris":["https://client.example.com/cb"],"client_name":"Test"}`
	rw := httptest.NewRecorder()
	mux.ServeHTTP(rw, httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body)))
	var registered struct {
		ID string `json:"client_id"`
	}
	_ = json.Unmarshal(rw.Body.Bytes(), &registered)
	query := "client_id=" + registered.ID + "&redirect_uri=" + url.QueryEscape("https://client.example.com/cb") + "&response_type=code&code_challenge_method=S256&code_challenge=" + strings.Repeat("a", 43)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/oauth/authorize?"+query, nil))
	want := "/api/auth/id/login?return_to=" + url.QueryEscape("/oauth/authorize?"+query)
	if w.Code != 303 || w.Header().Get("Location") != want || strings.Contains(w.Body.String(), "password") {
		t.Fatal("unauthenticated authorize did not go through Microapps ID", w.Code, w.Header().Get("Location"))
	}
}

func TestLocalCredentialRoutesRequireMicroappsID(t *testing.T) {
	h := New(&auth.Service{Config: auth.Config{BaseURL: "https://mail.example.com"}})
	mux := http.NewServeMux()
	h.Register(mux)
	for _, route := range []struct{ method, path string }{{"POST", "/auth/login"}, {"POST", "/auth/register"}, {"POST", "/auth/resend"}, {"GET", "/auth/verify"}, {"POST", "/auth/forgot"}, {"POST", "/auth/reset"}} {
		r := httptest.NewRequest(route.method, route.path, strings.NewReader(`{"email":"probe-nobody@example.test","password":"x"}`))
		r.Header.Set("Origin", "https://mail.example.com")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var body map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != 403 || body["code"] != "identity_required" || body["error"] != "Sign in with Microapps ID." {
			t.Errorf("%s %s: %d %s", route.method, route.path, w.Code, w.Body.String())
		}
	}
	// Without configured Microapps ID the login routes fail closed.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/auth/id/login", nil))
	if w.Code != 503 {
		t.Fatal("login worked without Microapps ID", w.Code)
	}
}
