package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	for _, v := range []struct {
		email string
		want  bool
	}{{"me@olegpustovit.com", true}, {"URSUS95@gmail.com", true}, {"@olegpustovit.com", false}, {"x@evil.olegpustovit.com", false}, {"x@olegpustovit.com.evil", false}, {"x@y@olegpustovit.com", false}, {"other@gmail.com", false}} {
		if Allowed(v.email) != v.want {
			t.Errorf("Allowed(%q)", v.email)
		}
	}
}
func TestMongoCredentialIsolationAndTokens(t *testing.T) {
	uri := os.Getenv("MAIL_TEST_MONGODB_URI")
	if uri == "" {
		t.Skip("set MAIL_TEST_MONGODB_URI for Mongo integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, e := New(ctx, Config{BaseURL: "https://mail.example.com", MongoURI: uri, EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(ctx)
	s.db = s.client.Database("mail_test_" + Random())
	defer s.db.Drop(ctx)
	if e = s.SaveAccount(ctx, "one@olegpustovit.com", "one@icloud.com", "password-secret"); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveAccount(ctx, "two@olegpustovit.com", "two@icloud.com", "other-secret"); e != nil {
		t.Fatal(e)
	}
	email, p, e := s.Credentials(ctx, "one@olegpustovit.com")
	if e != nil || email != "one@icloud.com" || p != "password-secret" {
		t.Fatalf("credentials mismatch %s %v", email, e)
	}
	a, e := s.Account(ctx, "one@olegpustovit.com")
	if e != nil {
		t.Fatal(e)
	}
	if string(a.Secret) == p {
		t.Fatal("plaintext stored")
	}
	if _, _, e = s.Credentials(ctx, "missing@olegpustovit.com"); e == nil {
		t.Fatal("missing account accepted")
	}
	a.Secret[len(a.Secret)-1] ^= 1
	if _, e = s.db.Collection("accounts").ReplaceOne(ctx, map[string]string{"_id": a.Email}, a); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Credentials(ctx, a.Email); e == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	token := Random()
	if e = s.Put(ctx, Record{ID: Hash(token), Kind: "code", Expires: time.Now().Add(time.Minute)}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get(ctx, token, "code", true); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get(ctx, token, "code", true); e != ErrUnauthorized {
		t.Fatal("replayed code accepted")
	}
	expired := Random()
	if e = s.Put(ctx, Record{ID: Hash(expired), Kind: "access", Expires: time.Now().Add(-time.Second)}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get(ctx, expired, "access", false); e != ErrUnauthorized {
		t.Fatal("expired token accepted before TTL cleanup")
	}
	clientID, access, otherAccess := Random(), Random(), Random()
	owner, otherOwner := "one@olegpustovit.com", "two@olegpustovit.com"
	for _, record := range []Record{{ID: Hash(clientID), Kind: "client", Data: `{"client_name":"Test agent"}`, Expires: time.Now().Add(time.Hour)}, {ID: Hash(access), Kind: "access", Email: owner, ClientID: clientID, Resource: s.Config.BaseURL + "/mcp", Expires: time.Now().Add(time.Hour)}, {ID: Hash(otherAccess), Kind: "access", Email: otherOwner, ClientID: clientID, Resource: s.Config.BaseURL + "/mcp", Expires: time.Now().Add(time.Hour)}} {
		if e = s.Put(ctx, record); e != nil {
			t.Fatal(e)
		}
	}
	request := httptest.NewRequest("POST", s.Config.BaseURL+"/mcp", nil)
	request.Header.Set("Authorization", "Bearer "+access)
	identity, actor, e := s.AuthenticateClient(request)
	if e != nil || identity != owner || actor != "mcp:"+clientID {
		t.Fatalf("client attribution failed: owner=%s actor=%s err=%v", identity, actor, e)
	}
	clients, e := s.Clients(ctx, owner)
	if e != nil || len(clients) != 1 || clients[0].Name != "Test agent" || clients[0].LastUsed.IsZero() {
		t.Fatalf("client list: %+v err=%v", clients, e)
	}
	if e = s.RevokeClient(ctx, owner, clientID); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.AuthenticateClient(request); e != ErrUnauthorized {
		t.Fatal("revoked client retained access")
	}
	request.Header.Set("Authorization", "Bearer "+otherAccess)
	if identity, _, e = s.AuthenticateClient(request); e != nil || identity != otherOwner {
		t.Fatal("revocation crossed owners")
	}
	current, second, otherSession := Random(), Random(), Random()
	for _, record := range []Record{{ID: Hash(current), Kind: "session", Email: owner, Expires: time.Now().Add(time.Hour)}, {ID: Hash(second), Kind: "session", Email: owner, Expires: time.Now().Add(time.Hour)}, {ID: Hash(otherSession), Kind: "session", Email: otherOwner, Expires: time.Now().Add(time.Hour)}} {
		if e = s.Put(ctx, record); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.RevokeOtherSessions(ctx, owner, current); e != nil {
		t.Fatal(e)
	}
	sessions, e := s.Sessions(ctx, owner, current)
	if e != nil || len(sessions) != 1 || !sessions[0].Current {
		t.Fatal("session revocation removed current browser or retained another one")
	}
	if _, e = s.Get(ctx, otherSession, "session", false); e != nil {
		t.Fatal("session revocation crossed owners")
	}
}
func TestLinkIdentity(t *testing.T) {
	uri := os.Getenv("MAIL_TEST_MONGODB_URI")
	if uri == "" {
		t.Skip("set MAIL_TEST_MONGODB_URI for Mongo integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	name := "mail_test_" + Random()
	s, e := New(ctx, Config{BaseURL: "https://mail.example.com", MongoURI: uri, Database: name, EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(ctx)
	defer func() { _ = s.db.Drop(ctx) }()
	owner, e := s.LinkIdentity(ctx, "sub-1", " Person@OlegPustovit.com ")
	if e != nil || owner != "person@olegpustovit.com" {
		t.Fatal("first sign-in did not link the normalized email", owner, e)
	}
	// A known subject keeps its owner even when the verified email changes.
	if owner, e = s.LinkIdentity(ctx, "sub-1", "ursus95@gmail.com"); e != nil || owner != "person@olegpustovit.com" {
		t.Fatal("changed email moved a linked subject", owner, e)
	}
	// Another subject cannot take an owner that is already linked.
	if _, e = s.LinkIdentity(ctx, "sub-2", "person@olegpustovit.com"); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("second subject linked an owned mailbox", e)
	}
	for _, email := range []string{"stranger@example.com", "", "evil@olegpustovit.com.evil.test"} {
		if _, e = s.LinkIdentity(ctx, "sub-3", email); !errors.Is(e, ErrUnauthorized) {
			t.Fatalf("%q was linked: %v", email, e)
		}
	}
	if _, e = s.LinkIdentity(ctx, "", "person@olegpustovit.com"); !errors.Is(e, ErrUnauthorized) {
		t.Fatal("empty subject accepted")
	}
	// Concurrent first sign-ins for one subject converge on one owner.
	results := make(chan string, 8)
	for range 8 {
		go func() { o, _ := s.LinkIdentity(ctx, "sub-race", "race@olegpustovit.com"); results <- o }()
	}
	for range 8 {
		if o := <-results; o != "race@olegpustovit.com" {
			t.Fatal("concurrent link diverged", o)
		}
	}
}

func TestIdentityConfigFromEnv(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	set := func(id, cookie string) {
		t.Setenv("MAIL_ID_CLIENT_ID", id)
		t.Setenv("MAIL_ID_COOKIE_KEY", cookie)
	}
	set("", key)
	if _, e := IdentityConfigFromEnv(); e == nil {
		t.Fatal("missing client id accepted")
	}
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(make([]byte, 16))} {
		set("app_mail", bad)
		if _, e := IdentityConfigFromEnv(); e == nil {
			t.Fatalf("cookie key %q accepted", bad)
		}
	}
	set("app_mail", key)
	cfg, e := IdentityConfigFromEnv()
	if e != nil || cfg.Issuer != "https://id.microapps.space" || cfg.CookieKey[0] != 9 {
		t.Fatal("valid configuration rejected", e)
	}
}
