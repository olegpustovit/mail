package mailsync

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/olegpustovit/mail/imap"
	"github.com/olegpustovit/mail/internal/pg"
	"github.com/olegpustovit/mail/smtp"
	"github.com/olegpustovit/mail/tools"
)

type Service struct {
	access      AccessGuard
	pool        *pgxpool.Pool
	credentials func(context.Context, string) (string, string, error)
	cipher      cipher.AEAD
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.Mutex
	sessions    map[string]map[commandLane]*session
	owners      map[string]*ownerState
	monitors    map[string]*monitor
	dialSync    func(context.Context, string, string, func()) (syncTransport, error)
	dialCommand func(context.Context, string, string) (*Connection, error)
	prefetch    chan prefetchRequest
	pushSession func(context.Context, string, string) (bool, error)
	pushSubject string
	pushHTTP    *http.Client
}

type Connection struct {
	Mail    commandClient
	Sender  sender
	Address string
}

type prefetchRequest struct{ owner, account string }
type sender interface {
	SetAliases([]string)
	SendEmail(context.Context, string, []string, string, string, smtp.SendOptions) error
	ReplyToEmail(context.Context, *imap.Email, string, bool, smtp.SendOptions) error
}
type commandClient interface {
	tools.EmailService
	UIDValidity(context.Context, string) (uint32, error)
	Closed() bool
	Close() error
	Relocate(context.Context, imap.Location, string, string) (imap.Location, error)
	ClearMoveMarker(context.Context, imap.Location, string) error
	RenameFolder(context.Context, string, string) error
	SearchPage(context.Context, string, string, imap.EmailFilters) (imap.SearchPage, error)
}

func (s *Service) Account(ctx context.Context, owner string) (string, error) {
	address, _, err := s.credentials(ctx, owner)
	return address, err
}

type session struct {
	gate        chan struct{}
	connection  *Connection
	fingerprint [32]byte
}

type commandLane uint8

const (
	interactiveLane commandLane = iota
	bulkLane
)

func New(ctx context.Context, dsn, key string, credentials func(context.Context, string) (string, string, error), guards ...AccessGuard) (*Service, error) {
	return newService(ctx, dsn, key, credentials, "", guards...)
}
func newService(ctx context.Context, dsn, key string, credentials func(context.Context, string) (string, string, error), schema string, guards ...AccessGuard) (*Service, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("invalid mail encryption key")
	}
	block, err := aes.NewCipher(decoded)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pool, err := pg.Open(ctx, dsn, schema)
	if err != nil {
		return nil, fmt.Errorf("connect mail sync: %w", err)
	}
	if err = pg.Migrate(ctx, pool, ddlMirror+ddlMoves+ddlOutbox); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate mail sync: %w", err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	s := &Service{pool: pool, cipher: aead, credentials: credentials, ctx: workerCtx, cancel: cancel, sessions: map[string]map[commandLane]*session{}, owners: map[string]*ownerState{}, monitors: map[string]*monitor{}, prefetch: make(chan prefetchRequest, 16), dialSync: func(ctx context.Context, address, password string, notify func()) (syncTransport, error) {
		return imap.NewSyncClient(ctx, address, password, notify)
	}}
	if len(guards) > 0 {
		s.access = guards[0]
	}
	s.dialCommand = func(ctx context.Context, address, password string) (*Connection, error) {
		client, err := imap.NewClientContext(ctx, address, password)
		if err != nil {
			return nil, err
		}
		return &Connection{Mail: client, Sender: smtp.NewClient(address, password, client.SaveSent), Address: address}, nil
	}
	pg.Sweep(workerCtx, pool, time.Minute, append(append([]string{sweepChangelog}, sweepMoves...), sweepOutbox...)...)
	fail := func(err error) (*Service, error) {
		cancel()
		pool.Close()
		return nil, err
	}
	if err = s.recoverOwner(ctx, ""); err != nil {
		return fail(err)
	}
	// A process crash during SMTP is ambiguous; never automatically send it twice.
	if _, err = pool.Exec(ctx, `UPDATE mail_outbox SET status = 'uncertain', error = 'Server restarted during delivery; check Sent before retrying.' WHERE status = 'sending'`); err != nil {
		return fail(err)
	}
	s.wg.Add(4)
	go s.runJobs()
	go s.runPush()
	go s.runRules()
	go s.runPrefetch()
	return s, nil
}

// Acquire shares one serialized command connection across browser and MCP requests.
func (s *Service) Acquire(ctx context.Context, owner string) (*Connection, func(), error) {
	return s.acquire(ctx, owner, interactiveLane)
}

func (s *Service) AcquireBulk(ctx context.Context, owner string) (*Connection, func(), error) {
	return s.acquire(ctx, owner, bulkLane)
}

func (s *Service) acquireForActor(ctx context.Context, owner, actor string) (*Connection, func(), error) {
	if strings.HasPrefix(actor, "mcp:") || strings.HasPrefix(actor, "prefetch:") {
		return s.AcquireBulk(ctx, owner)
	}
	return s.Acquire(ctx, owner)
}

func closeSession(ctx context.Context, entry *session) error {
	select {
	case entry.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if entry.connection != nil {
		_ = entry.connection.Mail.Close()
		entry.connection = nil
	}
	<-entry.gate
	return nil
}

func (s *Service) acquire(ctx context.Context, owner string, lane commandLane) (*Connection, func(), error) {
	s.mu.Lock()
	lanes := s.sessions[owner]
	if lanes == nil {
		lanes = map[commandLane]*session{}
		s.sessions[owner] = lanes
	}
	entry := lanes[lane]
	if entry == nil {
		entry = &session{gate: make(chan struct{}, 1)}
		lanes[lane] = entry
	}
	s.mu.Unlock()
	select {
	case entry.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, nil, s.ctx.Err()
	}
	release := sync.OnceFunc(func() { <-entry.gate })
	address, password, err := s.credentials(ctx, owner)
	if err != nil {
		release()
		return nil, nil, err
	}
	fingerprint := sha256.Sum256([]byte(address + "\x00" + password))
	if entry.connection != nil && (entry.fingerprint != fingerprint || entry.connection.Mail.Closed()) {
		_ = entry.connection.Mail.Close()
		entry.connection = nil
	}
	if entry.connection == nil {
		connection, err := s.dialCommand(ctx, address, password)
		if err != nil {
			release()
			return nil, nil, err
		}
		entry.connection = connection
		entry.fingerprint = fingerprint
	}
	borrowed := entry.connection
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		if client, ok := borrowed.Mail.(interface{ Abort() error }); ok {
			_ = client.Abort()
		}
		close(finished)
	})
	releaseBorrowed := sync.OnceFunc(func() {
		if !stop() {
			<-finished
		}
		release()
	})
	if err := ctx.Err(); err != nil {
		releaseBorrowed()
		return nil, nil, err
	}
	return borrowed, releaseBorrowed, nil
}

// Credential checks borrow the command slot instead of opening a third IMAP session.
func (s *Service) ValidateAccount(ctx context.Context, owner, address, password string) error {
	s.mu.Lock()
	entries := make([]*session, 0, len(s.sessions[owner]))
	for _, entry := range s.sessions[owner] {
		entries = append(entries, entry)
	}
	s.mu.Unlock()
	for _, entry := range entries {
		if err := closeSession(ctx, entry); err != nil {
			return err
		}
	}
	client, err := imap.NewClientContext(ctx, address, password)
	if err != nil {
		return err
	}
	_, err = client.ListFolders(ctx)
	return errors.Join(err, client.Close())
}

func (s *Service) Invalidate(ctx context.Context, owner string, disconnect bool) error {
	state := s.owner(owner)
	s.mu.Lock()
	state.generation++
	entries := make([]*session, 0, len(s.sessions[owner]))
	for _, entry := range s.sessions[owner] {
		entries = append(entries, entry)
	}
	m := s.monitors[owner]
	delete(s.monitors, owner)
	s.mu.Unlock()
	if m != nil {
		m.cancel()
		select {
		case <-m.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for _, entry := range entries {
		if err := closeSession(ctx, entry); err != nil {
			return err
		}
	}
	if !disconnect {
		resume, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_, err := s.Start(resume, owner)
		return err
	}
	state.write.Lock()
	defer state.write.Unlock()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	for _, table := range []string{"mail_messages", "mail_folders", "mail_thread_nodes", "mail_changelog", "mail_push_devices", "mail_rule_jobs", "mail_rule_applications", "mail_sync_status"} {
		if _, err = tx.Exec(ctx, "DELETE FROM "+table+" WHERE owner = $1", owner); err != nil {
			return err
		}
	}
	expires := time.Now().Add(14 * 24 * time.Hour)
	for _, q := range []string{
		`UPDATE mail_outbox SET status = 'cancelled' WHERE owner = $1 AND status = 'pending'`,
		`UPDATE mail_moves SET state = 'cancelled', expires = $2, next_attempt = NULL WHERE owner = $1`,
		`UPDATE mail_folder_ops SET state = 'cancelled', expires = $2 WHERE owner = $1`,
	} {
		args := []any{owner}
		if strings.Contains(q, "$2") {
			args = append(args, expires)
		}
		if _, err = tx.Exec(ctx, q, args...); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (s *Service) Close(ctx context.Context) error {
	s.cancel()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, lanes := range s.sessions {
		for _, entry := range lanes {
			if err := closeSession(ctx, entry); err != nil {
				return err
			}
		}
	}
	s.pool.Close()
	return nil
}

func (s *Service) keepSessions() {
	s.mu.Lock()
	type ownedEntry struct {
		owner string
		entry *session
	}
	var entries []ownedEntry
	for owner, lanes := range s.sessions {
		for _, entry := range lanes {
			entries = append(entries, ownedEntry{owner, entry})
		}
	}
	s.mu.Unlock()
	for _, owned := range entries {
		entry := owned.entry
		ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
		work, release, err := s.ownerWork(ctx, owned.owner)
		if err != nil {
			cancel()
			continue
		}
		ctx = work
		finish := func() { release(); cancel() }
		select {
		case entry.gate <- struct{}{}:
		case <-ctx.Done():
			finish()
			continue
		}
		if connection := entry.connection; connection != nil && !connection.Mail.Closed() {
			if keepAlive, ok := connection.Mail.(interface{ KeepAlive(context.Context) error }); ok {
				if err := keepAlive.KeepAlive(ctx); err != nil {
					_ = connection.Mail.Close()
					entry.connection = nil
				}
			}
		}
		<-entry.gate
		finish()
	}
}

func (s *Service) seal(data []byte) []byte {
	nonce := make([]byte, s.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return s.cipher.Seal(nonce, nonce, data, nil)
}
func (s *Service) open(data []byte) ([]byte, error) {
	n := s.cipher.NonceSize()
	if len(data) < n {
		return nil, errors.New("invalid encrypted mail")
	}
	return s.cipher.Open(nil, data[:n], data[n:], nil)
}

func (s *Service) runJobs() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	ticks := 0
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			ticks++
			if ticks%60 == 0 {
				if err := s.cleanOutbox(s.ctx); err != nil && !errors.Is(err, context.Canceled) {
					slog.Error("clean recovered outbox payloads", "error", err)
				}
				s.keepSessions()
			}
			if err := s.runRename(s.ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("mail folder recovery", "error", err)
			}
			if err := s.deliverNext(s.ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("mail outbox worker", "error", err)
			}
			if err := s.runMove(s.ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("mail relocation worker", "error", err)
			}
		}
	}
}
