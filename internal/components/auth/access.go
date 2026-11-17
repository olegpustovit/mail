package auth

import (
	"context"
	"errors"
	"time"

	idclient "github.com/olegpustovit/identity/idclient-go"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var ErrAccessDenied = errors.New("mail app access denied")
var ErrAccessUnavailable = errors.New("mail app access unavailable")

// EnableAccess configures the single confidential app before requests/workers.
func (s *Service) EnableAccess(cfg IdentityConfig) error {
	if !cfg.AccessEnabled {
		return nil
	}
	if s.access != nil {
		return nil
	}
	client, err := idclient.NewAccessClient(idclient.AccessConfig{Issuer: cfg.Issuer, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, PositiveTTL: 60 * time.Second})
	if err != nil {
		return errors.New("mail access checks require confidential Microapps ID credentials")
	}
	s.access = func(ctx context.Context, subject string, fresh bool) error {
		var d idclient.AccessDecision
		var err error
		if fresh {
			d, err = client.CheckFresh(ctx, subject)
		} else {
			d, err = client.Check(ctx, subject)
		}
		if err != nil {
			return ErrAccessUnavailable
		}
		if !d.Allowed {
			return ErrAccessDenied
		}
		return nil
	}
	return nil
}
func (s *Service) AccessEnabled() bool { return s.access != nil }
func (s *Service) Subject(ctx context.Context, owner string) (string, error) {
	if !Allowed(owner) {
		return "", ErrAccessDenied
	}
	var binding Identity
	err := s.db.Collection("identities").FindOne(ctx, bson.M{"email": owner}).Decode(&binding)
	if errors.Is(err, mongo.ErrNoDocuments) || err == nil && binding.Subject == "" {
		return "", ErrAccessDenied
	}
	if err != nil {
		return "", ErrAccessUnavailable
	}
	return binding.Subject, nil
}
func (s *Service) CheckSubject(ctx context.Context, subject string, fresh bool) error {
	if s.access == nil {
		return nil
	}
	if subject == "" {
		return ErrAccessDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.access(ctx, subject, fresh)
}
func (s *Service) CheckRecord(ctx context.Context, r Record, fresh bool) error {
	if s.access == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if r.Subject == "" {
		return ErrAccessDenied
	}
	subject, err := s.Subject(ctx, r.Email)
	if err != nil {
		return err
	}
	if subject != r.Subject {
		return ErrAccessDenied
	}
	return s.CheckSubject(ctx, subject, fresh)
}
func (s *Service) CheckOwner(ctx context.Context, owner string, fresh bool) error {
	if s.access == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	subject, err := s.Subject(ctx, owner)
	if err != nil {
		return err
	}
	return s.CheckSubject(ctx, subject, fresh)
}

// WatchAccess binds active work to the stored subject, including idle work. A
// fresh check every 25 seconds and a two-second bound cancel within 27 seconds.
func (s *Service) WatchAccess(parent context.Context, owner string) (context.Context, context.CancelFunc, error) {
	if s.access == nil {
		ctx, cancel := context.WithCancel(parent)
		return ctx, cancel, nil
	}
	initial, cancel := context.WithTimeout(parent, 2*time.Second)
	subject, err := s.Subject(initial, owner)
	cancel()
	if err != nil {
		ctx, stop := context.WithCancel(parent)
		stop()
		return ctx, stop, err
	}
	return watchChecks(parent, func(ctx context.Context, fresh bool) error {
		current, err := s.Subject(ctx, owner)
		if err != nil {
			return err
		}
		if current != subject {
			return ErrAccessDenied
		}
		return s.CheckSubject(ctx, subject, fresh)
	})
}
func watchChecks(parent context.Context, check func(context.Context, bool) error) (context.Context, context.CancelFunc, error) {
	ctx, stop := context.WithCancelCause(parent)
	cancel := func() { stop(context.Canceled) }
	bounded := func(fresh bool) error {
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return check(attempt, fresh)
	}
	if err := bounded(true); err != nil {
		stop(err)
		return ctx, cancel, err
	}
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := bounded(true); err != nil {
					stop(err)
					return
				}
			}
		}
	}()
	return ctx, cancel, nil
}
