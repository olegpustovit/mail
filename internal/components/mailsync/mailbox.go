package mailsync

import (
	"context"
	"errors"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/olegpustovit/mail/imap"
	"github.com/olegpustovit/mail/internal/pg"
	"github.com/olegpustovit/mail/smtp"
)

type Mailbox struct {
	s                     *Service
	owner, account, actor string
}

func (m *Mailbox) acquire(ctx context.Context) (*Connection, func(), error) {
	return m.s.acquireForActor(ctx, m.owner, m.actor)
}

type transactionKey struct{}

func Transaction(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, transactionKey{}, id)
}
func transactionID(ctx context.Context) string {
	id, _ := ctx.Value(transactionKey{}).(string)
	return id
}

func (s *Service) Mailbox(ctx context.Context, owner, actor string) (*Mailbox, error) {
	if strings.HasPrefix(actor, "mcp:") {
		s.touch(owner)
	}
	m, err := s.Start(ctx, owner)
	if err != nil {
		return nil, err
	}
	return &Mailbox{s: s, owner: owner, account: m.account, actor: actor}, nil
}
func (m *Mailbox) ListFolders(ctx context.Context) ([]string, error) {
	if err := m.s.WaitReady(ctx, m.owner); err != nil {
		return nil, err
	}
	folders, err := m.s.Folders(ctx, m.owner, m.account)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(folders))
	for i, f := range folders {
		names[i] = f.Name
	}
	return names, nil
}
func (m *Mailbox) UIDValidity(ctx context.Context, folder string) (uint32, error) {
	connection, release, err := m.acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer release()
	if connection.Address != m.account {
		return 0, errors.New("iCloud account changed")
	}
	return connection.Mail.UIDValidity(ctx, folder)
}
func (m *Mailbox) folder(ctx context.Context, name string) (Folder, error) {
	if err := m.s.WaitReady(ctx, m.owner); err != nil {
		return Folder{}, err
	}
	folder, err := m.s.folderByName(ctx, m.owner, m.account, name)
	if errors.Is(err, pg.ErrNoRows) {
		if err = m.s.Refresh(ctx, m.owner, "imap", "", name); err != nil {
			return folder, err
		}
		folder, err = m.s.folderByName(ctx, m.owner, m.account, name)
	}
	return folder, err
}
func (s *Service) folderByName(ctx context.Context, owner, account, name string) (Folder, error) {
	var d folderDoc
	if err := s.pool.QueryRow(ctx, `SELECT data FROM mail_folders WHERE owner = $1 AND account = $2 AND name = $3 LIMIT 1`, owner, account, name).Scan(&d); err != nil {
		return Folder{}, err
	}
	return *d.folder(), nil
}

// filter accumulates SQL conditions; "?" in a condition becomes the next $n argument.
type filter struct {
	conds []string
	args  []any
}

func (f *filter) add(cond string, args ...any) {
	for _, a := range args {
		f.args = append(f.args, a)
		cond = strings.Replace(cond, "?", "$"+strconv.Itoa(len(f.args)), 1)
	}
	f.conds = append(f.conds, cond)
}
func (f *filter) where() string {
	if len(f.conds) == 0 {
		return "TRUE"
	}
	return strings.Join(f.conds, " AND ")
}

// page appends ORDER BY/OFFSET/LIMIT and returns the row tail for loadMessages.
func (f *filter) page(offset, limit int) string {
	q := "WHERE " + f.where() + " ORDER BY date DESC, key OFFSET " + strconv.Itoa(max(offset, 0))
	if limit > 0 {
		q += " LIMIT " + strconv.Itoa(limit)
	}
	return q
}
func (s *Service) countMessages(ctx context.Context, f *filter) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM mail_messages WHERE "+f.where(), f.args...).Scan(&n)
	return n, err
}

// Text fields live in the jsonb payload; recipients are arrays. Patterns are quoted regexes matched case-insensitively.
const (
	fieldSubject = "(data->>'subject')"
	fieldFrom    = "(data->>'from')"
	fieldSnippet = "(data->>'snippet')"
	fieldTo      = "EXISTS (SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(data->'to') = 'array' THEN data->'to' ELSE '[]'::jsonb END) r WHERE r ~* ?)"
)

func (f *filter) anyText(pattern string) {
	f.add("("+fieldSubject+" ~* ? OR "+fieldFrom+" ~* ? OR "+fieldSnippet+" ~* ? OR "+fieldTo+")", pattern, pattern, pattern, pattern)
}

func mailFilter(folder, query string, filters imap.EmailFilters) *filter {
	f := &filter{}
	if folder != "" && folder != "*" {
		f.add("folder = ?", folder)
	}
	if filters.UnreadOnly {
		f.add("(data->>'unread')::boolean")
	}
	if filters.Since != nil {
		f.add("date >= ?", *filters.Since)
	} else if filters.LastDays > 0 {
		f.add("date >= ?", time.Now().AddDate(0, 0, -filters.LastDays))
	}
	if filters.Before != nil {
		f.add("date < ?", *filters.Before)
	}
	if query != "" {
		f.anyText(regexp.QuoteMeta(query))
	}
	return f
}
func (m *Mailbox) SearchEmails(ctx context.Context, folder, query string, filters imap.EmailFilters) ([]imap.Email, int, error) {
	f, err := m.folder(ctx, folder)
	if err != nil {
		return nil, 0, err
	}
	// During import and for full-body text queries, keep the existing IMAP search contract.
	if !f.Complete || query != "" {
		connection, release, err := m.acquire(ctx)
		if err != nil {
			return nil, 0, err
		}
		defer release()
		if connection.Address != m.account {
			return nil, 0, errors.New("iCloud account changed")
		}
		mail, total, err := connection.Mail.SearchEmails(ctx, folder, query, filters)
		for i := range mail {
			mail[i].Folder = folder
		}
		return mail, total, err
	}
	w := mailFilter(folder, query, filters)
	w.add("owner = ? AND account = ?", m.owner, m.account)
	count, err := m.s.countMessages(ctx, w)
	if err != nil {
		return nil, 0, err
	}
	stored, err := m.s.loadMessages(ctx, w.page(filters.Offset, filters.Limit), w.args...)
	if err != nil {
		return nil, 0, err
	}
	mail := make([]imap.Email, len(stored))
	for i, row := range stored {
		mail[i] = row.Email
	}
	return mail, count, nil
}
func (m *Mailbox) CountEmails(ctx context.Context, folder string, filters imap.EmailFilters) (int, error) {
	f, err := m.folder(ctx, folder)
	if err != nil {
		return 0, err
	}
	if filters.LastDays == 0 && filters.Since == nil && filters.Before == nil {
		if filters.UnreadOnly {
			return int(f.Unread), nil
		}
		return int(f.Total), nil
	}
	if !f.Complete {
		connection, release, err := m.acquire(ctx)
		if err != nil {
			return 0, err
		}
		defer release()
		return connection.Mail.CountEmails(ctx, folder, filters)
	}
	w := mailFilter(folder, "", filters)
	w.add("owner = ? AND account = ?", m.owner, m.account)
	return m.s.countMessages(ctx, w)
}

// CachedEmail reads only the requested immutable mailbox generation; cache misses still need live validation.
func (m *Mailbox) CachedEmail(ctx context.Context, folder, id string, validity uint32) (*imap.Email, error) {
	rows, err := m.s.loadMessages(ctx, `WHERE key = $1 AND owner = $2 AND account = $3 AND body_cached`, messageKey(m.owner, m.account, folder, validity, id), m.owner, m.account)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0].Email, nil
}

func (m *Mailbox) GetEmail(ctx context.Context, folder, id string) (*imap.Email, error) {
	var metadata Metadata
	rows, metadataErr := m.s.loadMessages(ctx, `WHERE owner = $1 AND account = $2 AND folder = $3 AND uid = $4 ORDER BY uidvalidity DESC LIMIT 1`, m.owner, m.account, folder, id)
	if metadataErr == nil && len(rows) == 0 {
		metadataErr = pg.ErrNoRows
	}
	if metadataErr == nil {
		metadata = rows[0]
	}
	if metadataErr == nil && metadata.BodyCached {
		cached := metadata.Email
		return &cached, nil
	}
	connection, release, err := m.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if connection.Address != m.account {
		return nil, errors.New("iCloud account changed")
	}
	email, err := connection.Mail.GetEmail(ctx, folder, id)
	if err != nil {
		return nil, err
	}
	email.Folder = folder
	if metadataErr == nil {
		email.ThreadID = metadata.ThreadID
		email.ListID = metadata.ListID
		email.Unsubscribe = metadata.Unsubscribe
		email.UnsubscribePost = metadata.UnsubscribePost
	}
	if email.Size <= 8<<20 {
		_ = m.s.cacheBody(ctx, m.owner, m.account, messageKey(m.owner, m.account, folder, email.UIDValidity, id), email)
	}
	return email, nil
}
func (m *Mailbox) GetAttachment(ctx context.Context, folder, id, filename string) (*imap.AttachmentData, error) {
	connection, release, err := m.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if connection.Address != m.account {
		return nil, errors.New("iCloud account changed")
	}
	return connection.Mail.GetAttachment(ctx, folder, id, filename)
}
func (m *Mailbox) change(ctx context.Context, folders []string, apply func(context.Context, *Connection) error) error {
	return m.changeCommand(ctx, folders, false, apply)
}
func (m *Mailbox) changeCommand(ctx context.Context, folders []string, allowRename bool, apply func(context.Context, *Connection) error) error {
	return m.s.change(ctx, m.owner, m.actor, transactionID(ctx), folders, func(ctx context.Context) error {
		connection, release, err := m.acquire(ctx)
		if err != nil {
			return err
		}
		defer release()
		if connection.Address != m.account {
			return errors.New("iCloud account changed")
		}
		if !allowRename {
			if err := m.s.checkRenamePending(ctx, m.owner, m.account); err != nil {
				return err
			}
		}
		return apply(ctx, connection)
	})
}
func (m *Mailbox) MarkRead(ctx context.Context, folder, id string, read bool) error {
	return m.change(ctx, []string{folder}, func(ctx context.Context, c *Connection) error { return c.Mail.MarkRead(ctx, folder, id, read) })
}
func (m *Mailbox) FlagEmail(ctx context.Context, folder, id, kind, color string) error {
	return m.change(ctx, []string{folder}, func(ctx context.Context, c *Connection) error { return c.Mail.FlagEmail(ctx, folder, id, kind, color) })
}
func (m *Mailbox) MoveEmail(ctx context.Context, from, to, id string) error {
	validity, err := m.UIDValidity(ctx, from)
	if err != nil {
		return err
	}
	return m.MoveWithValidity(ctx, imap.Location{Folder: from, ID: id, Validity: validity}, to)
}
func (m *Mailbox) DeleteEmail(ctx context.Context, folder, id string, permanent bool) error {
	if !permanent {
		folders, err := m.s.Folders(ctx, m.owner, m.account)
		if err != nil {
			return err
		}
		for _, target := range folders {
			if target.Role == "trash" {
				return m.MoveEmail(ctx, folder, target.Name, id)
			}
		}
		return errors.New("trash mailbox unavailable")
	}
	return m.change(ctx, []string{folder}, func(ctx context.Context, c *Connection) error { return c.Mail.DeleteEmail(ctx, folder, id, permanent) })
}
func (m *Mailbox) CreateFolder(ctx context.Context, name, parent string) error {
	return m.change(ctx, nil, func(ctx context.Context, c *Connection) error { return c.Mail.CreateFolder(ctx, name, parent) })
}
func (m *Mailbox) DeleteFolder(ctx context.Context, name string, force bool) (empty bool, count int, err error) {
	folders, err := m.s.Folders(ctx, m.owner, m.account)
	if err != nil {
		return false, 0, err
	}
	for _, folder := range folders {
		if folder.Name == name && folder.Role != "" {
			return false, 0, errors.New("system mailboxes cannot be deleted")
		}
	}
	err = m.change(ctx, nil, func(ctx context.Context, c *Connection) error {
		empty, count, err = c.Mail.DeleteFolder(ctx, name, force)
		return err
	})
	return
}
func (m *Mailbox) SaveDraft(ctx context.Context, from string, to []string, subject, body string, opts imap.DraftOptions) (id string, err error) {
	err = m.change(ctx, m.roleFolders(ctx, "drafts"), func(ctx context.Context, c *Connection) error {
		id, err = c.Mail.SaveDraft(ctx, from, to, subject, body, opts)
		return err
	})
	return
}

// roleFolders scopes the post-change refresh; nil (no such role yet) falls back to refreshing every folder.
func (m *Mailbox) roleFolders(ctx context.Context, role string) []string {
	folders, err := m.s.Folders(ctx, m.owner, m.account)
	if err != nil {
		return nil
	}
	for _, folder := range folders {
		if folder.Role == role {
			return []string{folder.Name}
		}
	}
	return nil
}
func (m *Mailbox) SendEmail(ctx context.Context, from string, to []string, subject, body string, opts smtp.SendOptions) error {
	return m.change(ctx, nil, func(ctx context.Context, c *Connection) error {
		identity, err := m.s.SenderIdentity(ctx, m.owner, from)
		if err != nil {
			return err
		}
		parsed, _ := mail.ParseAddress(identity)
		c.Sender.SetAliases([]string{parsed.Address})
		return c.Sender.SendEmail(ctx, identity, to, subject, body, opts)
	})
}
func (m *Mailbox) ReplyToEmail(ctx context.Context, original *imap.Email, body string, all bool, opts smtp.SendOptions) error {
	return m.change(ctx, nil, func(ctx context.Context, c *Connection) error {
		identity, err := m.s.SenderIdentity(ctx, m.owner, opts.From)
		if err != nil {
			return err
		}
		parsed, _ := mail.ParseAddress(identity)
		c.Sender.SetAliases([]string{parsed.Address})
		opts.From = identity
		return c.Sender.ReplyToEmail(ctx, original, body, all, opts)
	})
}

func (s *Service) MirrorSearch(ctx context.Context, owner, account, folder, query string, limit, offset int) ([]Metadata, int64, error) {
	if err := s.WaitReady(ctx, owner); err != nil {
		return nil, 0, err
	}
	f := mailFilter(folder, "", imap.EmailFilters{})
	if folder == "flagged" {
		f = &filter{}
		f.add("COALESCE(data->>'flagColor', '') <> ''")
	}
	if folder == "vip" {
		f = &filter{}
		prefs, err := s.Preferences(ctx, owner)
		if err != nil {
			return nil, 0, err
		}
		if len(prefs.VIP) == 0 {
			return []Metadata{}, 0, nil
		}
		senders := make([]string, len(prefs.VIP))
		args := make([]any, len(prefs.VIP))
		for i, sender := range prefs.VIP {
			senders[i] = fieldFrom + " ~* ?"
			args[i] = "(^|<)" + regexp.QuoteMeta(sender) + ">?$"
		}
		f.add("("+strings.Join(senders, " OR ")+")", args...)
	}
	if query != "" {
		if err := searchConditions(f, query); err != nil {
			return nil, 0, err
		}
	}
	f.add("owner = ? AND account = ?", owner, account)
	count, err := s.countMessages(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	mail, err := s.loadMessages(ctx, f.page(offset, min(max(limit, 1), 2000)), f.args...)
	return mail, int64(count), err
}

var searchToken = regexp.MustCompile(`(?:[^\s"]+|"[^"]*")+`)

func searchConditions(f *filter, query string) error {
	for _, token := range searchToken.FindAllString(query, -1) {
		key, value, hasKey := strings.Cut(token, ":")
		if !hasKey {
			value = key
			key = ""
		}
		value = strings.Trim(value, `"`)
		pattern := regexp.QuoteMeta(value)
		switch strings.ToLower(key) {
		case "from":
			f.add(fieldFrom+" ~* ?", pattern)
		case "subject":
			f.add(fieldSubject+" ~* ?", pattern)
		case "to":
			f.add(fieldTo, pattern)
		case "in":
			f.add("folder ~* ?", pattern)
		case "is":
			switch value {
			case "unread":
				f.add("(data->>'unread')::boolean")
			case "read":
				f.add("NOT (data->>'unread')::boolean")
			case "flagged":
				f.add("COALESCE(data->>'flagColor', '') <> ''")
			default:
				return errors.New("unknown is: search filter")
			}
		case "has":
			if value != "attachment" {
				return errors.New("unknown has: search filter")
			}
			f.add("jsonb_typeof(data->'attachments') = 'array' AND data->'attachments' <> '[]'::jsonb")
		case "after", "before":
			date, err := time.Parse("2006-01-02", value)
			if err != nil {
				return errors.New("search dates must use YYYY-MM-DD")
			}
			if key == "before" {
				f.add("date < ?", date)
			} else {
				f.add("date >= ?", date)
			}
		default:
			f.anyText(pattern)
		}
	}
	return nil
}
