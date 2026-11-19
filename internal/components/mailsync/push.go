package mailsync

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/netip"
	"net/url"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/jackc/pgx/v5"
	"github.com/olegpustovit/mail/internal/pg"
	"github.com/olegpustovit/mail/internal/publichttp"
)

type PushDevice struct {
	ID          string    `json:"id"`
	Owner       string    `json:"-"`
	Account     string    `json:"-"`
	Session     string    `json:"-"`
	Name        string    `json:"name"`
	Zone        string    `json:"zone"`
	Payload     []byte    `json:"-"`
	Cursor      int64     `json:"-"`
	NextAttempt time.Time `json:"-"`
	Error       string    `json:"error,omitempty"`
}
type PushRegistration struct {
	Subscription webpush.Subscription `json:"subscription"`
	Name         string               `json:"name"`
	Zone         string               `json:"zone"`
}
type pushKeys struct {
	ID      string
	Public  string
	Private []byte
}

func (s *Service) ConfigurePush(validSession func(context.Context, string, string) (bool, error), subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pushSession = validSession
	s.pushSubject = subject
	if s.pushHTTP == nil {
		s.pushHTTP = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: publichttp.DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 << 10}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
}

const pushCols = `id, owner, account, session, name, zone, payload, "cursor", next_attempt, error`

func scanPush(row pgx.CollectableRow) (PushDevice, error) {
	var d PushDevice
	err := row.Scan(&d.ID, &d.Owner, &d.Account, &d.Session, &d.Name, &d.Zone, &d.Payload, &d.Cursor, &d.NextAttempt, &d.Error)
	return d, err
}
func (s *Service) queryPush(ctx context.Context, sql string, args ...any) ([]PushDevice, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanPush)
}
func (s *Service) pushKeys(ctx context.Context) (pushKeys, error) {
	var keys pushKeys
	const query = "SELECT id, public, private FROM mail_push_keys WHERE id = 'vapid'"
	err := s.pool.QueryRow(ctx, query).Scan(&keys.ID, &keys.Public, &keys.Private)
	if !errors.Is(err, pg.ErrNoRows) {
		return keys, err
	}
	private, public, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		return keys, err
	}
	keys = pushKeys{ID: "vapid", Public: public, Private: s.seal([]byte(private))}
	_, err = s.pool.Exec(ctx, "INSERT INTO mail_push_keys (id, public, private) VALUES ($1, $2, $3)", keys.ID, keys.Public, keys.Private)
	if pg.IsUnique(err) {
		err = s.pool.QueryRow(ctx, query).Scan(&keys.ID, &keys.Public, &keys.Private)
	}
	return keys, err
}
func (s *Service) PushPublicKey(ctx context.Context) (string, error) {
	keys, err := s.pushKeys(ctx)
	return keys.Public, err
}
func validatePush(p PushRegistration) error {
	u, err := url.Parse(p.Subscription.Endpoint)
	if err != nil || len(p.Subscription.Endpoint) > 8192 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || (u.Port() != "" && u.Port() != "443") {
		return errors.New("invalid push endpoint")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publichttp.PublicAddress(ip) {
		return errors.New("private push endpoint")
	}
	auth, err := base64.RawURLEncoding.DecodeString(p.Subscription.Keys.Auth)
	if err != nil || len(auth) != 16 {
		return errors.New("invalid push authentication")
	}
	key, err := base64.RawURLEncoding.DecodeString(p.Subscription.Keys.P256dh)
	if err != nil {
		return errors.New("invalid push key")
	}
	if _, err = ecdh.P256().NewPublicKey(key); err != nil {
		return errors.New("invalid push key")
	}
	if len(p.Name) == 0 || len(p.Name) > 100 || strings.ContainsAny(p.Name, "\r\n\x00") {
		return errors.New("invalid device name")
	}
	if len(p.Zone) > 100 {
		return errors.New("invalid time zone")
	}
	_, err = time.LoadLocation(p.Zone)
	return err
}
func (s *Service) SavePushDevice(ctx context.Context, owner, session string, p PushRegistration) (PushDevice, error) {
	var d PushDevice
	if err := validatePush(p); err != nil {
		return d, err
	}
	s.mu.Lock()
	valid := s.pushSession
	s.mu.Unlock()
	if valid == nil {
		return d, errors.New("push unavailable")
	}
	ok, err := valid(ctx, owner, session)
	if err != nil {
		return d, err
	}
	if !ok {
		return d, errors.New("session expired")
	}
	state := s.owner(owner)
	state.write.Lock()
	defer state.write.Unlock()
	account, err := s.Account(ctx, owner)
	if err != nil {
		return d, err
	}
	id := identity(p.Subscription.Endpoint)
	var count int
	err = s.pool.QueryRow(ctx, "SELECT count(*) FROM mail_push_devices WHERE owner = $1 AND id <> $2", owner, id).Scan(&count)
	if err != nil {
		return d, err
	}
	if count >= 20 {
		return d, errors.New("too many devices")
	}
	cursor, err := s.Cursor(ctx, owner, account)
	if err != nil {
		return d, err
	}
	var existing int64
	err = s.pool.QueryRow(ctx, `SELECT "cursor" FROM mail_push_devices WHERE id = $1 AND owner = $2 AND account = $3`, id, owner, account).Scan(&existing)
	if err == nil {
		cursor = existing
	} else if !errors.Is(err, pg.ErrNoRows) {
		return d, err
	}
	raw, err := json.Marshal(p.Subscription)
	if err != nil {
		return d, err
	}
	d = PushDevice{ID: id, Owner: owner, Account: account, Session: session, Name: p.Name, Zone: p.Zone, Cursor: cursor, Payload: s.seal(raw), NextAttempt: time.Now().UTC()}
	// Possession of the subscription's endpoint and keys rebinds this browser after an account change.
	_, err = s.pool.Exec(ctx, `INSERT INTO mail_push_devices (`+pushCols+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET owner = $2, account = $3, session = $4, name = $5, zone = $6, payload = $7, "cursor" = $8, next_attempt = $9, error = $10`,
		d.ID, d.Owner, d.Account, d.Session, d.Name, d.Zone, d.Payload, d.Cursor, d.NextAttempt, d.Error)
	return d, err
}
func (s *Service) PushDevices(ctx context.Context, owner string) ([]PushDevice, error) {
	account, err := s.Account(ctx, owner)
	if err != nil {
		return nil, err
	}
	return s.queryPush(ctx, "SELECT "+pushCols+" FROM mail_push_devices WHERE owner = $1 AND account = $2", owner, account)
}
func (s *Service) RemovePushDevice(ctx context.Context, owner, id string) error {
	account, err := s.Account(ctx, owner)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, "DELETE FROM mail_push_devices WHERE id = $1 AND owner = $2 AND account = $3", id, owner, account)
	return err
}
func quietNow(p Preferences, now time.Time) bool {
	if !p.QuietHours {
		return false
	}
	clock := now.Format("15:04")
	if p.QuietStart < p.QuietEnd {
		return clock >= p.QuietStart && clock < p.QuietEnd
	}
	return clock >= p.QuietStart || clock < p.QuietEnd
}
func wantsNotification(p Preferences, account string, m Metadata, now time.Time) bool {
	if !m.Unread || p.Notifications == "none" || quietNow(p, now) {
		return false
	}
	if p.Notifications == "all" {
		return true
	}
	contains := func(values []string, value string) bool {
		for _, candidate := range values {
			if strings.EqualFold(mailAddress(candidate), mailAddress(value)) {
				return true
			}
		}
		return false
	}
	if contains(p.VIP, m.From) {
		return true
	}
	if m.ListID != "" {
		return false
	}
	for _, to := range m.To {
		if strings.EqualFold(mailAddress(to), account) {
			return true
		}
		for _, identity := range p.Identities {
			if strings.EqualFold(mailAddress(to), identity.Address) {
				return true
			}
		}
	}
	return false
}
func mailAddress(value string) string {
	if address, err := mail.ParseAddress(value); err == nil {
		return address.Address
	}
	return strings.TrimSpace(value)
}
func cutText(value string, limit int) string {
	r := []rune(value)
	if len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return value
}
func (s *Service) dropPushDevice(ctx context.Context, d PushDevice) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM mail_push_devices WHERE id = $1 AND owner = $2 AND session = $3", d.ID, d.Owner, d.Session)
	return err
}
func (s *Service) pushDevice(ctx context.Context, d PushDevice, valid func(context.Context, string, string) (bool, error), subject string, client *http.Client) error {
	work, release, err := s.ownerWork(ctx, d.Owner)
	if err != nil {
		return err
	}
	defer release()
	ctx = work
	ok, err := valid(ctx, d.Owner, d.Session)
	if err != nil {
		return err
	}
	account, err := s.Account(ctx, d.Owner)
	if err != nil {
		return err
	}
	if !ok || account != d.Account {
		return s.dropPushDevice(ctx, d)
	}
	p, err := s.Preferences(ctx, d.Owner)
	if err != nil {
		return err
	}
	zone, err := time.LoadLocation(d.Zone)
	if err != nil {
		return err
	}
	high, err := s.Cursor(ctx, d.Owner, d.Account)
	if err != nil {
		return err
	}
	// shortcut: Changes pages 1000 rows, so arrivals are filtered here; a full page without 30 arrivals advances only to its last row.
	window, err := s.Changes(ctx, d.Owner, d.Account, d.Cursor)
	if err != nil {
		return err
	}
	var changes []Change
	for _, c := range window {
		if c.Arrival && c.Sequence <= high && len(changes) < 30 {
			changes = append(changes, c)
		}
	}
	reach := high
	if len(window) == 1000 {
		reach = min(high, window[len(window)-1].Sequence)
	}
	next := time.Now().Add(2 * time.Second)
	failure := ""
	for _, change := range changes {
		now := time.Now()
		if change.Message != nil && now.Sub(change.At) < 5*time.Minute {
			current, err := s.messageByKey(ctx, d.Owner, d.Account, change.Key)
			if err != nil && !errors.Is(err, pg.ErrNoRows) {
				return err
			}
			if err == nil && wantsNotification(p, account, current, now.In(zone)) {
				keys, err := s.pushKeys(ctx)
				if err != nil {
					return err
				}
				private, err := s.open(keys.Private)
				if err != nil {
					return err
				}
				raw, err := s.open(d.Payload)
				if err != nil {
					return err
				}
				var sub webpush.Subscription
				if err = json.Unmarshal(raw, &sub); err != nil {
					return err
				}
				folders, err := s.Folders(ctx, d.Owner, d.Account)
				if err != nil {
					return err
				}
				var unread uint32
				for _, folder := range folders {
					if folder.Role == "inbox" || strings.EqualFold(folder.Name, "INBOX") {
						unread += folder.Unread
					}
				}
				payload, _ := json.Marshal(map[string]any{"title": cutText(current.From, 120), "body": cutText(current.Subject, 300), "tag": change.Key, "unread": unread, "data": map[string]any{"folder": current.Folder, "id": current.ID, "validity": current.UIDValidity, "account": d.Account, "owner": d.Owner}})
				response, sendErr := webpush.SendNotificationWithContext(ctx, payload, &sub, &webpush.Options{HTTPClient: client, Subscriber: subject, VAPIDPublicKey: keys.Public, VAPIDPrivateKey: string(private), TTL: 300, Topic: change.Key[:32], Urgency: webpush.UrgencyNormal})
				code := 0
				if response != nil {
					code = response.StatusCode
					_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
					_ = response.Body.Close()
				}
				if code == 404 || code == 410 {
					return s.dropPushDevice(ctx, d)
				}
				if sendErr != nil || code < 200 || code >= 300 {
					failure = "Push delivery failed; retrying."
					next = now.Add(time.Minute)
					break
				}
			}
		}
		d.Cursor = change.Sequence
	}
	if failure == "" && len(changes) < 30 {
		d.Cursor = reach
	}
	_, err = s.pool.Exec(ctx, `UPDATE mail_push_devices SET "cursor" = $4, next_attempt = $5, error = $6 WHERE id = $1 AND owner = $2 AND session = $3`, d.ID, d.Owner, d.Session, d.Cursor, next, failure)
	return err
}
func (s *Service) runPush() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			valid, subject, client := s.pushSession, s.pushSubject, s.pushHTTP
			s.mu.Unlock()
			if valid == nil {
				continue
			}
			devices, err := s.queryPush(s.ctx, "SELECT "+pushCols+" FROM mail_push_devices WHERE next_attempt <= now() ORDER BY next_attempt LIMIT 20")
			if err != nil {
				continue
			}
			for _, device := range devices {
				if err = s.pushDevice(s.ctx, device, valid, subject, client); err != nil {
					_, _ = s.pool.Exec(s.ctx, "UPDATE mail_push_devices SET next_attempt = $3, error = 'Push unavailable; retrying.' WHERE id = $1 AND session = $2", device.ID, device.Session, time.Now().Add(time.Minute))
				}
			}
		}
	}
}
