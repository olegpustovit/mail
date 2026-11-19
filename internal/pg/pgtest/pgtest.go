// Package pgtest gives each test a private schema on the Postgres named by MAIL_TEST_POSTGRES_URI.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/olegpustovit/mail/internal/pg"
)

// New skips the test without MAIL_TEST_POSTGRES_URI; otherwise it returns the URI and a fresh schema dropped on cleanup.
func New(t testing.TB) (dsn, schema string) {
	t.Helper()
	dsn = os.Getenv("MAIL_TEST_POSTGRES_URI")
	if dsn == "" {
		t.Skip("set MAIL_TEST_POSTGRES_URI for Postgres integration")
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	schema = "t_" + hex.EncodeToString(b)
	t.Cleanup(func() {
		pool, err := pg.Open(context.Background(), dsn, "public")
		if err != nil {
			return
		}
		defer pool.Close()
		_, _ = pool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})
	return dsn, schema
}
