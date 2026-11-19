// Package pg opens the shared Postgres pool and applies idempotent schema DDL.
package pg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNoRows = pgx.ErrNoRows

var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Open connects to Postgres and pins search_path to schema ("" means "public"), creating it when missing.
func Open(ctx context.Context, dsn, schema string) (*pgxpool.Pool, error) {
	if dsn == "" {
		return nil, errors.New("missing Postgres configuration")
	}
	if schema == "" {
		schema = "public"
	}
	if !schemaName.MatchString(schema) {
		return nil, fmt.Errorf("invalid schema name %q", schema)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse Postgres URI: %w", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	if schema != "public" {
		boot, err := pgx.ConnectConfig(ctx, cfg.ConnConfig)
		if err != nil {
			return nil, fmt.Errorf("connect Postgres: %w", err)
		}
		_, err = boot.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema)
		_ = boot.Close(ctx)
		if err != nil {
			return nil, fmt.Errorf("create schema: %w", err)
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect Postgres: %w", err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping Postgres: %w", err)
	}
	return pool, nil
}

// Migrate runs idempotent DDL (CREATE ... IF NOT EXISTS only), serialized across processes by an advisory lock.
func Migrate(ctx context.Context, pool *pgxpool.Pool, ddl string) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, "SELECT pg_advisory_lock(7710001)"); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(7710001)") }()
	_, err = conn.Exec(ctx, ddl)
	return err
}

// IsUnique reports a unique-constraint violation (Mongo's duplicate key).
func IsUnique(err error) bool {
	var e *pgconn.PgError
	return errors.As(err, &e) && e.Code == "23505"
}

// Sweep deletes expired rows (Mongo TTL indexes) every interval until ctx ends. Each stmt is a full DELETE.
func Sweep(ctx context.Context, pool *pgxpool.Pool, interval time.Duration, stmts ...string) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for _, q := range stmts {
					if _, err := pool.Exec(ctx, q); err != nil && ctx.Err() == nil {
						slog.Warn("expire rows", "error", err)
					}
				}
			}
		}
	}()
}
