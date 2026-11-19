package mailsync

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// AccessGuard is configured before the hosted worker loops start. Stdio and
// explicitly independent service maintenance need not attach a human principal.
type AccessGuard func(context.Context, string) (context.Context, context.CancelFunc, error)

var ErrAccessPaused = errors.New("mail owner access is paused")

func (s *Service) ownerWork(ctx context.Context, owner string) (context.Context, context.CancelFunc, error) {
	if s.access == nil {
		next, cancel := context.WithCancel(ctx)
		return next, cancel, nil
	}
	next, cancel, err := s.access(ctx, owner)
	if err != nil {
		return next, cancel, errors.Join(ErrAccessPaused, err)
	}
	return next, cancel, nil
}

// A denied/unavailable owner pauses dispatch without consuming attempts or
// claiming a send. Bounded metadata maintenance keeps other owners dispatchable.
func (s *Service) jobWork(ctx context.Context, owner, collection, id, field string) (context.Context, context.CancelFunc, bool, error) {
	next, cancel, err := s.ownerWork(ctx, owner)
	if err == nil {
		return next, cancel, true, nil
	}
	if cancel != nil {
		cancel()
	}
	maintenance, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	// collection and field are code constants, never user input.
	_, updateErr := s.pool.Exec(maintenance, fmt.Sprintf("UPDATE %s SET %s = $1 WHERE id = $2 AND owner = $3", collection, field), time.Now().Add(30*time.Second), id, owner)
	return next, func() {}, false, updateErr
}
