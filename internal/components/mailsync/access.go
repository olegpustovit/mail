package mailsync

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
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
	_, updateErr := s.db.Collection(collection).UpdateOne(maintenance, bson.M{"_id": id, "owner": owner}, bson.M{"$set": bson.M{field: time.Now().Add(30 * time.Second)}})
	return next, func() {}, false, updateErr
}
