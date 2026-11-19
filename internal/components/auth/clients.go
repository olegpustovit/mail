package auth

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/olegpustovit/mail/internal/pg"
)

type ClientGrant struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Granted  time.Time `json:"granted"`
	LastUsed time.Time `json:"lastUsed"`
}

func (s *Service) Clients(ctx context.Context, owner string) ([]ClientGrant, error) {
	records, err := s.records(ctx, "email=$1 AND kind IN ('access','refresh') AND expires > now()", owner)
	if err != nil {
		return nil, err
	}
	grants := map[string]ClientGrant{}
	for _, record := range records {
		if record.ClientID == "" {
			continue
		}
		grant := grants[record.ClientID]
		grant.ID = record.ClientID
		if !record.Created.IsZero() && (grant.Granted.IsZero() || record.Created.Before(grant.Granted)) {
			grant.Granted = record.Created
		}
		if record.LastUsed.After(grant.LastUsed) {
			grant.LastUsed = record.LastUsed
		}
		grants[grant.ID] = grant
	}
	result := make([]ClientGrant, 0, len(grants))
	for _, grant := range grants {
		var registration Record
		if err = s.pool.QueryRow(ctx, "SELECT data FROM auth WHERE id=$1 AND kind='client'", Hash(grant.ID)).Scan(&registration.Data); err != nil && !errors.Is(err, pg.ErrNoRows) {
			return nil, err
		}
		var data struct {
			Name string `json:"client_name"`
		}
		_ = json.Unmarshal([]byte(registration.Data), &data)
		grant.Name = data.Name
		if grant.Name == "" {
			grant.Name = "MCP client " + grant.ID[:min(8, len(grant.ID))]
		}
		result = append(result, grant)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].LastUsed.After(result[j].LastUsed) })
	return result, nil
}
func (s *Service) RevokeClient(ctx context.Context, owner, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM auth WHERE email=$1 AND client_id=$2 AND kind IN ('access','refresh','code')", owner, id)
	return err
}

type BrowserSession struct {
	ID      string    `json:"id"`
	Agent   string    `json:"agent"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	Current bool      `json:"current"`
}

func (s *Service) ActiveSession(ctx context.Context, owner, hash string) (bool, error) {
	var count int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM auth WHERE id=$1 AND kind='session' AND email=$2 AND expires > now()", hash, owner).Scan(&count)
	return count == 1, err
}

func (s *Service) Sessions(ctx context.Context, owner, current string) ([]BrowserSession, error) {
	records, err := s.records(ctx, "email=$1 AND kind='session' AND expires > now()", owner)
	if err != nil {
		return nil, err
	}
	result := make([]BrowserSession, 0, len(records))
	for _, record := range records {
		result = append(result, BrowserSession{ID: record.ID, Agent: record.Data, Created: record.Created, Expires: record.Expires, Current: record.ID == Hash(current)})
	}
	return result, nil
}
func (s *Service) RevokeOtherSessions(ctx context.Context, owner, current string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM auth WHERE email=$1 AND kind='session' AND id <> $2", owner, Hash(current))
	return err
}
