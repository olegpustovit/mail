package mailsync

import (
	"context"
	"log/slog"
	"time"
)

func (s *Service) queuePrefetch(owner, account string) {
	select {
	case s.prefetch <- prefetchRequest{owner: owner, account: account}:
	default:
	}
}

func (s *Service) runPrefetch() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case request := <-s.prefetch:
			ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
			if err := s.prefetchBodies(ctx, request); err != nil && ctx.Err() == nil {
				slog.Warn("prefetch recent message bodies", "owner", request.owner, "error", err)
			}
			cancel()
		}
	}
}

func (s *Service) prefetchBodies(ctx context.Context, request prefetchRequest) error {
	work, release, err := s.ownerWork(ctx, request.owner)
	if err != nil {
		return err
	}
	defer release()
	ctx = work
	messages, err := s.loadMessages(ctx, `WHERE owner = $1 AND account = $2 AND folder = 'INBOX' AND NOT body_cached ORDER BY date DESC LIMIT 50`, request.owner, request.account)
	if err != nil {
		return err
	}
	mailbox := &Mailbox{s: s, owner: request.owner, account: request.account, actor: "mcp:prefetch"}
	for _, message := range messages {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if message.Size > 8<<20 {
			continue
		}
		email, err := mailbox.GetEmail(ctx, "INBOX", message.ID)
		if err != nil {
			slog.Warn("prefetch message body", "owner", request.owner, "uid", message.ID, "error", err)
			continue
		}
		err = s.cacheBody(ctx, request.owner, request.account, message.Key, email)
		if err != nil {
			return err
		}
	}
	return nil
}
