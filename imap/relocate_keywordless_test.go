package imap

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-imap/client"
	imapv2 "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// keywordlessSession behaves like iCloud's Junk mailbox: it cannot hold custom keywords.
type keywordlessSession struct {
	imapserver.Session
	mode     string // "permanent-flags" advertises no keywords; "dropped" advertises them but discards them
	selected string
}

func (s *keywordlessSession) Select(mailbox string, options *imapv2.SelectOptions) (*imapv2.SelectData, error) {
	data, err := s.Session.Select(mailbox, options)
	s.selected = mailbox
	if err == nil && mailbox == "Junk" && s.mode == "permanent-flags" {
		data.PermanentFlags = []imapv2.Flag{imapv2.FlagSeen, imapv2.FlagFlagged, imapv2.FlagDeleted, imapv2.FlagAnswered, imapv2.FlagDraft}
	}
	return data, err
}

func (s *keywordlessSession) Store(w *imapserver.FetchWriter, set imapv2.NumSet, flags *imapv2.StoreFlags, options *imapv2.StoreOptions) error {
	if s.selected == "Junk" && s.mode == "dropped" {
		var kept []imapv2.Flag
		for _, flag := range flags.Flags {
			if !strings.HasPrefix(strings.ToLower(string(flag)), "$terminalmail_") {
				kept = append(kept, flag)
			}
		}
		flags = &imapv2.StoreFlags{Op: flags.Op, Silent: flags.Silent, Flags: kept}
	}
	return s.Session.Store(w, set, flags, options)
}

func TestRelocateFromKeywordlessMailbox(t *testing.T) {
	for _, mode := range []string{"permanent-flags", "dropped", "no-uidplus"} {
		t.Run(mode, func(t *testing.T) { testRelocateFromKeywordlessMailbox(t, mode) })
	}
}

func testRelocateFromKeywordlessMailbox(t *testing.T, mode string) {
	backend := imapmemserver.New()
	user := imapmemserver.NewUser("test", "password")
	for _, name := range []string{"INBOX", "Junk", "Deleted Messages"} {
		if err := user.Create(name, nil); err != nil {
			t.Fatal(err)
		}
	}
	backend.AddUser(user)
	caps := imapv2.CapSet{imapv2.CapIMAP4rev1: {}}
	if mode != "no-uidplus" {
		caps[imapv2.CapUIDPlus] = struct{}{}
	}
	server := imapserver.New(&imapserver.Options{NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
		return &keywordlessSession{Session: backend.NewSession(), mode: mode}, nil, nil
	}, InsecureAuth: true, Caps: caps})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); <-done })
	message := func(subject string) *strings.Reader {
		return strings.NewReader("From: spam@example.com\r\nSubject: " + subject + "\r\n\r\nBody")
	}
	for _, folder := range []string{"Junk", "Junk", "Deleted Messages"} {
		if _, err = user.Append(folder, message("No Message-ID"), &imapv2.AppendOptions{Flags: []imapv2.Flag{imapv2.FlagSeen}}); err != nil {
			t.Fatal(err)
		}
	}
	wire, err := client.Dial(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer wire.Close()
	if err = wire.Login("test", "password"); err != nil {
		t.Fatal(err)
	}
	c := &Client{client: wire, username: "test"}
	ctx := context.Background()
	validity, err := c.UIDValidity(ctx, "Junk")
	if err != nil {
		t.Fatal(err)
	}
	from := Location{Folder: "Junk", ID: "1", Validity: validity}
	marker := "$TerminalMail_keywordless_test"
	location, err := c.Relocate(ctx, from, "Deleted Messages", marker)
	if mode == "no-uidplus" {
		if !errors.Is(err, ErrMarkerUnsupported) {
			t.Fatalf("unsafe fallback accepted: %v", err)
		}
		if count, err := c.CountEmails(ctx, "Junk", EmailFilters{}); err != nil || count != 2 {
			t.Fatal("unsupported move modified source", count, err)
		}
		return
	}
	if err != nil || location.Folder != "Deleted Messages" || location.ID != "2" {
		t.Fatalf("move=%+v err=%v", location, err)
	}
	if count, err := c.CountEmails(ctx, "Junk", EmailFilters{}); err != nil || count != 1 {
		t.Fatal("source was not removed or too much was removed", count, err)
	}
	if count, err := c.CountEmails(ctx, "Deleted Messages", EmailFilters{}); err != nil || count != 2 {
		t.Fatal("destination does not hold exactly one new copy", count, err)
	}
	if err = c.ClearMoveMarker(ctx, location, marker); err != nil {
		t.Fatal(err)
	}
	// Deleting through the public path must work from the keywordless mailbox too.
	if err = c.DeleteEmail(ctx, "Junk", "2", false); err != nil {
		t.Fatal("delete from keywordless mailbox failed", err)
	}
	if count, err := c.CountEmails(ctx, "Junk", EmailFilters{}); err != nil || count != 0 {
		t.Fatal("deleted message remains in Junk", count, err)
	}
	if count, err := c.CountEmails(ctx, "Deleted Messages", EmailFilters{}); err != nil || count != 3 {
		t.Fatal("deleted message is not in trash", count, err)
	}
}
