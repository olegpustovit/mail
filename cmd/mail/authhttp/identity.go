package authhttp

import (
	"context"
	"net/http"
	"net/url"
	"time"

	idclient "github.com/olegpustovit/identity/idclient-go"

	"github.com/olegpustovit/mail/internal/components/auth"
)

const sessionCookie = "__Host-mail_session"

// EnableIdentity connects the handler to Microapps ID. It performs provider discovery, so call it at startup.
func (h *Handler) EnableIdentity(ctx context.Context, cfg auth.IdentityConfig) error {
	if err := h.s.EnableAccess(cfg); err != nil {
		return err
	}
	client, err := idclient.New(ctx, idclient.Config{
		Issuer: cfg.Issuer, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		RedirectURL: h.s.Config.BaseURL + "/api/auth/id/callback", CookieKey: cfg.CookieKey,
		ResolveUnverifiedUser: func(ctx context.Context, claims idclient.Claims) (string, error) {
			return h.s.ResolveBoundIdentity(ctx, claims.Subject, claims.Email)
		},
		ResolveUser: func(ctx context.Context, claims idclient.Claims) (string, error) {
			if err := h.s.CheckSubject(ctx, claims.Subject, true); err != nil {
				return "", err
			}
			return h.s.LinkIdentity(ctx, claims.Subject, claims.Email)
		},
		Sessions: identitySessions{h},
	})
	if err != nil {
		return err
	}
	h.id = client
	return nil
}

// identityRequired answers every retired local credential route.
func identityRequired(w http.ResponseWriter, _ *http.Request) {
	jsonResponse(w, http.StatusForbidden, map[string]string{"code": "identity_required", "error": "Sign in with Microapps ID."})
}

func (h *Handler) identity(handle func(*idclient.Client, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.id == nil {
			fail(w, http.StatusServiceUnavailable, "identity_unavailable")
			return
		}
		handle(h.id, w, r)
	}
}

// loginURL starts Microapps ID sign-in and returns to a local path afterwards.
func loginURL(returnTo string) string {
	return "/api/auth/id/login?return_to=" + url.QueryEscape(returnTo)
}

type identitySessions struct{ h *Handler }

// Create replaces any existing browser session with a fresh one for the verified mailbox owner.
func (s identitySessions) Create(w http.ResponseWriter, r *http.Request, email string) error {
	if !auth.Allowed(email) {
		return auth.ErrUnauthorized
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err = s.h.s.Delete(r.Context(), c.Value); err != nil {
			return err
		}
	}
	subject, err := s.h.s.Subject(r.Context(), email)
	if err != nil && s.h.s.AccessEnabled() {
		return err
	}
	if err := s.h.s.CheckSubject(r.Context(), subject, false); err != nil {
		return err
	}
	session := auth.Random()
	ua := r.UserAgent()
	if err := s.h.s.Put(r.Context(), auth.Record{ID: auth.Hash(session), Kind: "session", Email: email, Subject: subject, Data: ua[:min(len(ua), 300)], Expires: time.Now().Add(7 * 24 * time.Hour)}); err != nil {
		return err
	}
	s.h.cookie(w, sessionCookie, session, 7*86400)
	return nil
}

// Clear revokes this browser's session and its local data.
func (s identitySessions) Clear(w http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err = s.h.s.Delete(r.Context(), c.Value); err != nil {
			return err
		}
	}
	s.h.cookie(w, sessionCookie, "", -1)
	w.Header().Set("Clear-Site-Data", `"storage"`)
	return nil
}
