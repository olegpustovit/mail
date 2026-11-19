package mailsync

import (
	"context"
	"errors"
	"time"

	"github.com/olegpustovit/mail/imap"
)

type RenameOperation struct {
	ID string `json:"id"`
	FolderRename
	Error             string    `json:"error,omitempty"`
	ReferencesUpdated bool      `json:"referencesUpdated"`
	Created           time.Time `json:"created"`
}

func (s *Service) RenameOperations(ctx context.Context, owner string) ([]RenameOperation, error) {
	account, err := s.Account(ctx, owner)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, "SELECT "+opColumns+" FROM mail_folder_ops WHERE owner = $1 AND account = $2 AND state = 'pending' ORDER BY created", owner, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []RenameOperation{}
	for rows.Next() {
		var op folderOperation
		if err = rows.Scan(op.fields()...); err != nil {
			return nil, err
		}
		result = append(result, RenameOperation{ID: op.ID, FolderRename: op.FolderRename, Error: op.Error, ReferencesUpdated: op.ReferencesUpdated, Created: op.Created})
	}
	return result, rows.Err()
}
func (s *Service) RetryRename(ctx context.Context, owner, id string) error {
	account, err := s.Account(ctx, owner)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE mail_folder_ops SET next_attempt = now(), error = '' WHERE id = $1 AND owner = $2 AND account = $3 AND state = 'pending'`, id, owner, account)
	return err
}
func (s *Service) CancelRename(ctx context.Context, owner, id string) error {
	box, err := s.Mailbox(ctx, owner, "web")
	if err != nil {
		return err
	}
	return box.changeCommand(ctx, nil, true, func(ctx context.Context, c *Connection) error {
		scope := "id = $1 AND owner = $2 AND account = $3 AND state = 'pending' AND NOT references_updated"
		op, err := s.loadOp(ctx, scope, id, owner, box.account)
		if err != nil {
			return errors.New("rename already applied; retry recovery instead")
		}
		validity, err := c.Mail.UIDValidity(ctx, op.From)
		if err != nil || validity != op.Validity {
			return errors.Join(imap.ErrLocationChanged, err)
		}
		result, err := s.pool.Exec(ctx, "UPDATE mail_folder_ops SET state = 'cancelled', expires = $4, error = '' WHERE "+scope, id, owner, box.account, time.Now().Add(14*24*time.Hour))
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return errors.New("rename already changed")
		}
		return nil
	})
}
