package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/olegpustovit/mail/internal/pg"
)

var ErrUnauthorized = errors.New("unauthorized")

// Schema defaults to "public"; only tests override it with a disposable name.
type Config struct{ BaseURL, PostgresURI, EncryptionKey, Schema string }

const ddl = `
CREATE TABLE IF NOT EXISTS auth (
	id text PRIMARY KEY, subject text NOT NULL DEFAULT '', kind text NOT NULL DEFAULT '', email text NOT NULL DEFAULT '',
	expires timestamptz, data text NOT NULL DEFAULT '', client_id text NOT NULL DEFAULT '', redirect text NOT NULL DEFAULT '',
	challenge text NOT NULL DEFAULT '', resource text NOT NULL DEFAULT '', family text NOT NULL DEFAULT '',
	created timestamptz, last_used timestamptz);
CREATE INDEX IF NOT EXISTS auth_expires ON auth (expires);
CREATE INDEX IF NOT EXISTS auth_email_kind ON auth (email, kind);
CREATE INDEX IF NOT EXISTS auth_family ON auth (family) WHERE family <> '';
CREATE TABLE IF NOT EXISTS accounts (email text PRIMARY KEY, icloud_email text NOT NULL DEFAULT '', secret bytea);
CREATE TABLE IF NOT EXISTS identities (subject text PRIMARY KEY, email text NOT NULL UNIQUE, created timestamptz NOT NULL);`

const recordCols = `id, subject, kind, email, expires, data, client_id, redirect, challenge, resource, family, created, last_used`

func nz(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
func scanRecord(row pgx.Row) (Record, error) {
	var r Record
	var exp, created, used *time.Time
	if err := row.Scan(&r.ID, &r.Subject, &r.Kind, &r.Email, &exp, &r.Data, &r.ClientID, &r.Redirect, &r.Challenge, &r.Resource, &r.Family, &created, &used); err != nil {
		return r, err
	}
	for _, p := range []struct {
		to   *time.Time
		from *time.Time
	}{{&r.Expires, exp}, {&r.Created, created}, {&r.LastUsed, used}} {
		if p.from != nil {
			*p.to = *p.from
		}
	}
	return r, nil
}
func (s *Service) records(ctx context.Context, where string, args ...any) ([]Record, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+recordCols+" FROM auth WHERE "+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type Service struct {
	Config Config
	pool   *pgxpool.Pool
	stop   context.CancelFunc
	cipher cipher.AEAD
	access func(context.Context, string, bool) error
}
type Record struct {
	Subject   string `json:"-"`
	ID        string
	Kind      string
	Email     string
	Expires   time.Time
	Data      string
	ClientID  string
	Redirect  string
	Challenge string
	Resource  string
	Family    string
	Created   time.Time
	LastUsed  time.Time
}
type Account struct {
	Email       string
	ICloudEmail string
	Secret      []byte `json:"-"`
}

func Allowed(email string) bool {
	email = strings.ToLower(email)
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return false
	}
	return email == "ursus95@gmail.com" || (strings.HasSuffix(email, "@olegpustovit.com") && strings.Count(email, "@") == 1 && len(email) > len("@olegpustovit.com"))
}
func Random() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func New(ctx context.Context, c Config) (*Service, error) {
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("MAIL_BASE_URL must be an HTTPS origin")
	}
	key, e := base64.StdEncoding.DecodeString(c.EncryptionKey)
	if e != nil || len(key) != 32 {
		return nil, errors.New("MAIL_ENCRYPTION_KEY must encode 32 bytes in base64")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	pool, e := pg.Open(ctx, c.PostgresURI, c.Schema)
	if e != nil {
		return nil, e
	}
	if e = pg.Migrate(ctx, pool, ddl); e != nil {
		pool.Close()
		return nil, e
	}
	sweep, stop := context.WithCancel(context.Background())
	pg.Sweep(sweep, pool, time.Minute, "DELETE FROM auth WHERE expires < now()")
	return &Service{Config: c, pool: pool, stop: stop, cipher: a}, nil
}
func (s *Service) Close(context.Context) error { s.stop(); s.pool.Close(); return nil }

func (s *Service) Put(ctx context.Context, r Record) error {
	if r.Created.IsZero() {
		r.Created = time.Now().UTC()
	}
	_, e := s.pool.Exec(ctx, "INSERT INTO auth ("+recordCols+") VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
		r.ID, r.Subject, r.Kind, r.Email, nz(r.Expires), r.Data, r.ClientID, r.Redirect, r.Challenge, r.Resource, r.Family, nz(r.Created), nz(r.LastUsed))
	return e
}
func (s *Service) Get(ctx context.Context, id, kind string, consume bool) (Record, error) {
	q := "SELECT " + recordCols + " FROM auth WHERE id=$1 AND kind=$2 AND expires > now()"
	if consume {
		q = "DELETE FROM auth WHERE id=$1 AND kind=$2 AND expires > now() RETURNING " + recordCols
	}
	r, e := scanRecord(s.pool.QueryRow(ctx, q, Hash(id), kind))
	if errors.Is(e, pg.ErrNoRows) {
		return r, ErrUnauthorized
	}
	return r, e
}
func (s *Service) Revoke(ctx context.Context, token string) error {
	r, e := s.Get(ctx, token, "refresh", false)
	if errors.Is(e, ErrUnauthorized) {
		r, e = s.Get(ctx, token, "access", false)
	}
	if errors.Is(e, ErrUnauthorized) {
		return nil
	}
	if e != nil {
		return e
	}
	_, e = s.pool.Exec(ctx, "DELETE FROM auth WHERE family=$1", r.Family)
	return e
}
func (s *Service) Delete(ctx context.Context, token string) error {
	_, e := s.pool.Exec(ctx, "DELETE FROM auth WHERE id=$1", Hash(token))
	return e
}
func (s *Service) Account(ctx context.Context, email string) (Account, error) {
	var a Account
	e := s.pool.QueryRow(ctx, "SELECT email, icloud_email, secret FROM accounts WHERE email=$1", email).Scan(&a.Email, &a.ICloudEmail, &a.Secret)
	if errors.Is(e, pg.ErrNoRows) {
		return a, nil
	}
	return a, e
}
func (s *Service) SaveAccount(ctx context.Context, email, icloud, password string) error {
	nonce := make([]byte, s.cipher.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return e
	}
	secret := s.cipher.Seal(nonce, nonce, []byte(password), []byte(email))
	_, e := s.pool.Exec(ctx, "INSERT INTO accounts (email, icloud_email, secret) VALUES ($1,$2,$3) ON CONFLICT (email) DO UPDATE SET icloud_email=EXCLUDED.icloud_email, secret=EXCLUDED.secret", email, icloud, secret)
	return e
}
func (s *Service) DeleteAccount(ctx context.Context, email string) error {
	_, e := s.pool.Exec(ctx, "DELETE FROM accounts WHERE email=$1", email)
	return e
}
func (s *Service) Credentials(ctx context.Context, email string) (string, string, error) {
	if err := s.CheckOwner(ctx, email, false); err != nil {
		return "", "", err
	}
	a, e := s.Account(ctx, email)
	if e != nil {
		return "", "", e
	}
	n := s.cipher.NonceSize()
	if len(a.Secret) < n {
		return "", "", errors.New("connect an iCloud account first")
	}
	p, e := s.cipher.Open(nil, a.Secret[:n], a.Secret[n:], []byte(email))
	return a.ICloudEmail, string(p), e
}

func (s *Service) ConnectedOwners(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, "SELECT email FROM accounts WHERE secret IS NOT NULL AND length(secret) > 0")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var owners []string
	for rows.Next() {
		var owner string
		if err = rows.Scan(&owner); err != nil {
			return nil, err
		}
		owners = append(owners, owner)
	}
	return owners, rows.Err()
}

func ConfigFromEnv() Config {
	return Config{BaseURL: strings.TrimRight(os.Getenv("MAIL_BASE_URL"), "/"), PostgresURI: os.Getenv("MAIL_POSTGRES_URI"), EncryptionKey: os.Getenv("MAIL_ENCRYPTION_KEY")}
}
func (s *Service) Authenticate(r *http.Request) (string, error) {
	email, _, err := s.AuthenticateClient(r)
	return email, err
}
func (s *Service) AuthenticateClient(r *http.Request) (string, string, error) {
	parts := strings.Split(r.Header.Get("Authorization"), " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", "", ErrUnauthorized
	}
	rec, e := s.Get(r.Context(), parts[1], "access", false)
	if e != nil {
		return "", "", e
	}
	if !Allowed(rec.Email) || rec.Resource != s.Config.BaseURL+"/mcp" {
		return "", "", ErrUnauthorized
	}
	if err := s.CheckRecord(r.Context(), rec, false); err != nil {
		return "", "", err
	}
	result, err := s.pool.Exec(r.Context(), "UPDATE auth SET last_used=$2 WHERE id=$1 AND kind='access'", rec.ID, time.Now().UTC())
	if err != nil {
		return "", "", err
	}
	if result.RowsAffected() == 0 {
		return "", "", ErrUnauthorized
	}
	return rec.Email, "mcp:" + rec.ClientID, nil
}

// Identity links one Microapps ID subject to the mailbox owner email.
type Identity struct {
	Subject string
	Email   string
	Created time.Time
}

// LinkIdentity maps a verified Microapps ID subject to a mailbox owner and returns that owner's email.
// A known subject keeps its original owner even if the Microapps ID email later changes, so an email
// change can never move a subject onto another owner's mailbox. A new subject links by exact
// normalized email to the existing owner data, and an email already linked to another subject is denied.
func (s *Service) LinkIdentity(ctx context.Context, subject, email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if subject == "" || len(subject) > 256 || !Allowed(email) {
		return "", ErrUnauthorized
	}
	find := func() (string, error) {
		var linked Identity
		e := s.pool.QueryRow(ctx, "SELECT subject, email, created FROM identities WHERE subject=$1", subject).Scan(&linked.Subject, &linked.Email, &linked.Created)
		if errors.Is(e, pg.ErrNoRows) {
			return "", ErrUnauthorized
		}
		if e != nil {
			return "", e
		}
		if !Allowed(linked.Email) {
			return "", ErrUnauthorized
		}
		return linked.Email, nil
	}
	if owner, e := find(); e == nil || !errors.Is(e, ErrUnauthorized) {
		return owner, e
	}
	_, e := s.pool.Exec(ctx, "INSERT INTO identities (subject, email, created) VALUES ($1,$2,$3)", subject, email, time.Now().UTC())
	if pg.IsUnique(e) {
		// A concurrent first sign-in for the same subject converges; any other duplicate is a different subject owning this email.
		return find()
	}
	if e != nil {
		return "", e
	}
	return email, nil
}

// IdentityConfig configures the Microapps ID client. All of it is required: it is the only sign-in method.
type IdentityConfig struct {
	AccessEnabled                  bool
	Issuer, ClientID, ClientSecret string
	CookieKey                      [32]byte
}

func IdentityConfigFromEnv() (IdentityConfig, error) {
	issuer := strings.TrimRight(os.Getenv("MAIL_ID_ISSUER"), "/")
	if issuer == "" {
		issuer = "https://id.microapps.space"
	}
	cfg := IdentityConfig{Issuer: issuer, ClientID: os.Getenv("MAIL_ID_CLIENT_ID"), ClientSecret: os.Getenv("MAIL_ID_CLIENT_SECRET")}
	switch os.Getenv("MAIL_ID_ACCESS_ENABLED") {
	case "", "false":
	case "true":
		cfg.AccessEnabled = true
	default:
		return cfg, errors.New("MAIL_ID_ACCESS_ENABLED must be true or false")
	}
	if cfg.AccessEnabled && cfg.ClientSecret == "" {
		return cfg, errors.New("mail access enforcement requires confidential client credentials")
	}
	if cfg.ClientID == "" {
		return cfg, errors.New("MAIL_ID_CLIENT_ID is required")
	}
	key, e := base64.StdEncoding.DecodeString(os.Getenv("MAIL_ID_COOKIE_KEY"))
	if e != nil || len(key) != 32 || [32]byte(key) == [32]byte{} {
		return cfg, errors.New("MAIL_ID_COOKIE_KEY must be a base64-encoded independent random 32-byte key")
	}
	copy(cfg.CookieKey[:], key)
	return cfg, nil
}

// ResolveBoundIdentity reads an existing subject mapping without linking email.
func (s *Service) ResolveBoundIdentity(ctx context.Context, subject, email string) (string, error) {
	if subject == "" || !Allowed(email) {
		return "", ErrUnauthorized
	}
	if err := s.CheckSubject(ctx, subject, true); err != nil {
		return "", err
	}
	var linked Identity
	if err := s.pool.QueryRow(ctx, "SELECT subject, email, created FROM identities WHERE subject=$1", subject).Scan(&linked.Subject, &linked.Email, &linked.Created); err != nil {
		return "", ErrUnauthorized
	}
	if !Allowed(linked.Email) {
		return "", ErrUnauthorized
	}
	return linked.Email, nil
}
