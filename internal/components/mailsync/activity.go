package mailsync

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/olegpustovit/mail/internal/pg"
)

func (s *Service) Activity(ctx context.Context, owner, account string) ([]Change, error) {
	changes, err := s.queryChanges(ctx, `WHERE owner = $1 AND account = $2 AND committed AND actor LIKE 'mcp:%' AND entity IN ('msg', 'folder') ORDER BY seq DESC LIMIT 100`, owner, account)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	result := make([]Change, 0, len(changes))
	for _, change := range changes {
		if change.MoveTransaction != "" {
			if seen[change.MoveTransaction] {
				continue
			}
			seen[change.MoveTransaction] = true
		}
		result = append(result, change)
	}
	return result, nil
}
func (s *Service) UndoActivity(ctx context.Context, owner, account string, sequence int64) error {
	changes, err := s.queryChanges(ctx, `WHERE owner = $1 AND account = $2 AND seq = $3 AND committed AND actor LIKE 'mcp:%'`, owner, account, sequence)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		return pg.ErrNoRows
	}
	change := changes[0]
	mailbox, err := s.Mailbox(ctx, owner, "web")
	if err != nil {
		return err
	}
	if mailbox.account != account {
		return errors.New("iCloud account changed")
	}
	if change.MoveTransaction != "" {
		return mailbox.UndoMove(ctx, change.MoveTransaction)
	}
	before, after := change.Before, change.Message
	if before == nil || after == nil || change.Op != "put" || before.Key != after.Key {
		return errors.New("this activity cannot be reversed")
	}
	return mailbox.change(ctx, []string{after.Folder}, func(ctx context.Context, c *Connection) error {
		current, err := s.messageByKey(ctx, owner, account, after.Key)
		if err != nil {
			return err
		}
		if current.Version != sequence {
			return errors.New("message changed after this activity")
		}
		live, err := c.Mail.GetEmail(ctx, after.Folder, after.ID)
		if err != nil {
			return err
		}
		if live.UIDValidity != after.UIDValidity || live.Unread != after.Unread || live.FlagColor != after.FlagColor {
			return errors.New("message changed on iCloud after this activity")
		}
		if before.Unread != after.Unread {
			return c.Mail.MarkRead(ctx, after.Folder, after.ID, !before.Unread)
		}
		if before.FlagColor != after.FlagColor {
			kind := "follow-up"
			if before.FlagColor == "" {
				kind = "none"
			}
			return c.Mail.FlagEmail(ctx, after.Folder, after.ID, kind, before.FlagColor)
		}
		return errors.New("this activity has no reversible flag change")
	})
}
func (s *Service) Watch(owner string) func() {
	state := s.owner(owner)
	s.mu.Lock()
	state.viewers++
	state.active = time.Now()
	s.mu.Unlock()
	return sync.OnceFunc(func() { s.mu.Lock(); state.viewers--; state.active = time.Now(); s.mu.Unlock() })
}
func (s *Service) touch(owner string) {
	state := s.owner(owner)
	s.mu.Lock()
	state.active = time.Now()
	s.mu.Unlock()
}
