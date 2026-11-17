package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var ErrUnauthorized = errors.New("unauthorized")

// Database defaults to "mail"; only tests override it with a disposable name.
type Config struct{ BaseURL, MongoURI, EncryptionKey, Database string }
type Service struct {
	Config Config
	client *mongo.Client
	db     *mongo.Database
	cipher cipher.AEAD
	access func(context.Context, string, bool) error
}
type Record struct {
	Subject   string    `bson:"subject,omitempty" json:"-"`
	ID        string    `bson:"_id"`
	Kind      string    `bson:"kind"`
	Email     string    `bson:"email,omitempty"`
	Expires   time.Time `bson:"expires,omitempty"`
	Data      string    `bson:"data,omitempty"`
	ClientID  string    `bson:"client_id,omitempty"`
	Redirect  string    `bson:"redirect,omitempty"`
	Challenge string    `bson:"challenge,omitempty"`
	Resource  string    `bson:"resource,omitempty"`
	Family    string    `bson:"family,omitempty"`
	Created   time.Time `bson:"created,omitempty"`
	LastUsed  time.Time `bson:"last_used,omitempty"`
}
type Account struct {
	Email       string `bson:"_id"`
	ICloudEmail string `bson:"icloud_email"`
	Secret      []byte `bson:"secret" json:"-"`
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
	if c.MongoURI == "" {
		return nil, errors.New("missing MongoDB configuration")
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
	client, e := mongo.Connect(options.Client().ApplyURI(c.MongoURI).SetTimeout(10 * time.Second))
	if e != nil {
		return nil, fmt.Errorf("connect MongoDB: %w", e)
	}
	if e = client.Ping(ctx, nil); e != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("ping MongoDB: %w", e)
	}
	database := c.Database
	if database == "" {
		database = "mail"
	}
	s := &Service{Config: c, client: client, db: client.Database(database), cipher: a}
	_, e = s.db.Collection("auth").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "expires", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)})
	if e == nil {
		_, e = s.db.Collection("identities").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)})
	}
	if e != nil {
		_ = client.Disconnect(ctx)
		return nil, e
	}
	return s, nil
}
func (s *Service) Close(ctx context.Context) error { return s.client.Disconnect(ctx) }

func (s *Service) Put(ctx context.Context, r Record) error {
	if r.Created.IsZero() {
		r.Created = time.Now().UTC()
	}
	_, e := s.db.Collection("auth").InsertOne(ctx, r)
	return e
}
func (s *Service) Get(ctx context.Context, id, kind string, consume bool) (Record, error) {
	var r Record
	filter := bson.M{"_id": Hash(id), "kind": kind, "expires": bson.M{"$gt": time.Now()}}
	var e error
	if consume {
		e = s.db.Collection("auth").FindOneAndDelete(ctx, filter).Decode(&r)
	} else {
		e = s.db.Collection("auth").FindOne(ctx, filter).Decode(&r)
	}
	if errors.Is(e, mongo.ErrNoDocuments) {
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
	_, e = s.db.Collection("auth").DeleteMany(ctx, bson.M{"family": r.Family})
	return e
}
func (s *Service) Delete(ctx context.Context, token string) error {
	_, e := s.db.Collection("auth").DeleteOne(ctx, bson.M{"_id": Hash(token)})
	return e
}
func (s *Service) Account(ctx context.Context, email string) (Account, error) {
	var a Account
	e := s.db.Collection("accounts").FindOne(ctx, bson.M{"_id": email}).Decode(&a)
	if errors.Is(e, mongo.ErrNoDocuments) {
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
	_, e := s.db.Collection("accounts").ReplaceOne(ctx, bson.M{"_id": email}, Account{email, icloud, secret}, options.Replace().SetUpsert(true))
	return e
}
func (s *Service) DeleteAccount(ctx context.Context, email string) error {
	_, e := s.db.Collection("accounts").DeleteOne(ctx, bson.M{"_id": email})
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
	rows, err := s.db.Collection("accounts").Find(ctx, bson.M{"secret": bson.M{"$type": "binData"}}, options.Find().SetProjection(bson.M{"_id": 1}))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close(ctx) }()
	var accounts []Account
	if err = rows.All(ctx, &accounts); err != nil {
		return nil, err
	}
	owners := make([]string, len(accounts))
	for i, account := range accounts {
		owners[i] = account.Email
	}
	return owners, nil
}

func ConfigFromEnv() Config {
	return Config{BaseURL: strings.TrimRight(os.Getenv("MAIL_BASE_URL"), "/"), MongoURI: os.Getenv("MAIL_MONGODB_URI"), EncryptionKey: os.Getenv("MAIL_ENCRYPTION_KEY")}
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
	result, err := s.db.Collection("auth").UpdateOne(r.Context(), bson.M{"_id": rec.ID, "kind": "access"}, bson.M{"$set": bson.M{"last_used": time.Now().UTC()}})
	if err != nil {
		return "", "", err
	}
	if result.MatchedCount == 0 {
		return "", "", ErrUnauthorized
	}
	return rec.Email, "mcp:" + rec.ClientID, nil
}

// Identity links one Microapps ID subject to the mailbox owner email.
type Identity struct {
	Subject string    `bson:"_id"`
	Email   string    `bson:"email"`
	Created time.Time `bson:"created"`
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
	coll := s.db.Collection("identities")
	find := func() (string, error) {
		var linked Identity
		e := coll.FindOne(ctx, bson.M{"_id": subject}).Decode(&linked)
		if errors.Is(e, mongo.ErrNoDocuments) {
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
	_, e := coll.InsertOne(ctx, Identity{Subject: subject, Email: email, Created: time.Now().UTC()})
	if mongo.IsDuplicateKeyError(e) {
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
