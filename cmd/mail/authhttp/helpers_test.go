package authhttp

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/olegpustovit/mail/internal/components/auth"
	"github.com/olegpustovit/mail/internal/pg/pgtest"
)

// testService opens an auth service in a private pgtest schema that is dropped afterwards.
func testService(t *testing.T) *auth.Service {
	t.Helper()
	ctx := context.Background()
	uri, schema := pgtest.New(t)
	s, err := auth.New(ctx, auth.Config{BaseURL: "https://mail.example.com", PostgresURI: uri, Schema: schema, EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = s.Close(c)
	})
	return s
}
