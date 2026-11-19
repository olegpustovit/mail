package mailsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/olegpustovit/mail/internal/pg"
)

type Identity struct {
	Address   string `json:"address"`
	Name      string `json:"name"`
	Signature string `json:"signature"`
}
type Rule struct {
	ID         string          `json:"id"`
	Field      string          `json:"field"`
	Match      string          `json:"match"`
	Value      string          `json:"value"`
	Action     string          `json:"action"`
	Target     string          `json:"target"`
	Enabled    bool            `json:"enabled"`
	Conditions []RuleCondition `json:"conditions,omitempty"`
	Actions    []RuleAction    `json:"actions,omitempty"`
}
type Preferences struct {
	Theme          string            `json:"theme"`
	Signal         bool              `json:"signal"`
	Density        string            `json:"density"`
	ReadingFont    string            `json:"readingFont"`
	Motion         string            `json:"motion"`
	KeyPreset      string            `json:"keyPreset"`
	Keymap         map[string]string `json:"keymap"`
	Notifications  string            `json:"notifications"`
	QuietHours     bool              `json:"quietHours"`
	QuietStart     string            `json:"quietStart"`
	QuietEnd       string            `json:"quietEnd"`
	UndoSeconds    int               `json:"undoSeconds"`
	RemoteContent  string            `json:"remoteContent"`
	AllowedSenders []string          `json:"allowedSenders"`
	StripTracking  bool              `json:"stripTracking"`
	VIP            []string          `json:"vip"`
	Identities     []Identity        `json:"identities"`
	Rules          []Rule            `json:"rules"`
}

func defaultPreferences() Preferences {
	return Preferences{Theme: "system", Density: "default", ReadingFont: "sans", Motion: "system", KeyPreset: "gmail", Keymap: map[string]string{}, Notifications: "none", QuietStart: "22:00", QuietEnd: "07:30", UndoSeconds: 10, RemoteContent: "block", StripTracking: true, AllowedSenders: []string{}, VIP: []string{}, Identities: []Identity{}, Rules: []Rule{}}
}
func (s *Service) Preferences(ctx context.Context, owner string) (Preferences, error) {
	p := defaultPreferences()
	// Unmarshalling over the defaults keeps them for fields the stored document lacks.
	err := s.pool.QueryRow(ctx, "SELECT data FROM mail_preferences WHERE id = $1", owner).Scan(&p)
	if errors.Is(err, pg.ErrNoRows) {
		return p, nil
	}
	return p, err
}
func validChoice(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
func (p Preferences) validate() error {
	if !validChoice(p.Theme, "system", "light", "dark") || !validChoice(p.Density, "compact", "default", "comfy") || !validChoice(p.ReadingFont, "sans", "mono") || !validChoice(p.Motion, "system", "full", "reduced") || !validChoice(p.KeyPreset, "gmail", "apple", "custom") || !validChoice(p.Notifications, "all", "vip", "none") || !validChoice(p.RemoteContent, "block", "proxy", "original") {
		return errors.New("invalid preference value")
	}
	if p.UndoSeconds != 5 && p.UndoSeconds != 10 && p.UndoSeconds != 20 && p.UndoSeconds != 30 {
		return errors.New("invalid undo duration")
	}
	for _, clock := range []string{p.QuietStart, p.QuietEnd} {
		if _, err := time.Parse("15:04", clock); err != nil || len(clock) != 5 {
			return errors.New("invalid quiet hours")
		}
	}
	if len(p.VIP) > 1000 || len(p.AllowedSenders) > 1000 || len(p.Identities) > 30 || len(p.Rules) > 100 || len(p.Keymap) > 100 {
		return errors.New("too many preferences")
	}
	for _, addresses := range [][]string{p.VIP, p.AllowedSenders} {
		for _, address := range addresses {
			parsed, err := mail.ParseAddress(address)
			if err != nil || parsed.Address != address {
				return errors.New("invalid sender address")
			}
		}
	}
	identities := make(map[string]bool)
	for _, identity := range p.Identities {
		parsed, err := mail.ParseAddress(identity.Address)
		if err != nil || parsed.Address != identity.Address || len(identity.Signature) > 10000 || len(identity.Name) > 100 || strings.ContainsAny(identity.Name, "\r\n\x00") || identities[strings.ToLower(identity.Address)] {
			return errors.New("invalid identity")
		}
		identities[strings.ToLower(identity.Address)] = true
	}
	rules := make(map[string]bool)
	for _, rule := range p.Rules {
		if err := rule.validate(); err != nil {
			return err
		}
		if rules[rule.ID] {
			return errors.New("duplicate rule ID")
		}
		rules[rule.ID] = true
	}
	for action, key := range p.Keymap {
		if len(action) > 40 || len(key) > 40 || key == "" {
			return errors.New("invalid key binding")
		}
	}
	return nil
}
func (s *Service) SavePreferences(ctx context.Context, owner string, p Preferences) error {
	return s.changePreferences(ctx, owner, func(current *Preferences) error { *current = p; return nil })
}
func (s *Service) PatchPreferences(ctx context.Context, owner string, patch json.RawMessage) error {
	return s.changePreferences(ctx, owner, func(p *Preferences) error {
		decoder := json.NewDecoder(bytes.NewReader(patch))
		decoder.DisallowUnknownFields()
		return decoder.Decode(p)
	})
}
func (s *Service) changePreferences(ctx context.Context, owner string, change func(*Preferences) error) error {
	state := s.owner(owner)
	state.write.Lock()
	defer state.write.Unlock()
	if err := s.recoverOwner(ctx, owner); err != nil {
		return err
	}
	p, err := s.Preferences(ctx, owner)
	if err != nil {
		return err
	}
	if err = change(&p); err != nil {
		return err
	}
	if err = p.validate(); err != nil {
		return err
	}
	account, err := s.Account(ctx, owner)
	if err != nil {
		return err
	}
	return s.commitLocked(ctx, owner, account, "web", "", []Change{{Entity: "pref", Op: "put", Key: owner, Preferences: &p}})
}

func (s *Service) SenderIdentity(ctx context.Context, owner, requested string) (string, error) {
	account, err := s.Account(ctx, owner)
	if err != nil {
		return "", err
	}
	prefs, err := s.Preferences(ctx, owner)
	if err != nil {
		return "", err
	}
	if requested == "" {
		requested = account
	}
	parsed, err := mail.ParseAddress(requested)
	if err != nil {
		return "", err
	}
	requested = parsed.Address
	for _, identity := range prefs.Identities {
		if strings.EqualFold(identity.Address, requested) {
			return (&mail.Address{Name: identity.Name, Address: identity.Address}).String(), nil
		}
	}
	if strings.EqualFold(requested, account) {
		return account, nil
	}
	return "", errors.New("sender is not a configured identity")
}
