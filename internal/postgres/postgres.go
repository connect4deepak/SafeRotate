// Package postgres is the Postgres connector: it changes login roles and
// reports which sessions use each role (the usage evidence).
package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Conn struct{ pool *pgxpool.Pool }

func Connect(ctx context.Context, url string) (*Conn, error) {
	p, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return &Conn{pool: p}, nil
}

func (c *Conn) Close() { c.pool.Close() }

// EnableWithPassword sets a new password on role and allows it to log in.
func (c *Conn) EnableWithPassword(ctx context.Context, role, password string) error {
	_, err := c.pool.Exec(ctx, "ALTER ROLE "+pgx.Identifier{role}.Sanitize()+
		" WITH LOGIN PASSWORD "+quoteLiteral(password))
	return err
}

// Disable stops role from logging in. Its password is kept so a rollback
// is a single Enable, and the next rotation overwrites it.
func (c *Conn) Disable(ctx context.Context, role string) error {
	_, err := c.pool.Exec(ctx, "ALTER ROLE "+pgx.Identifier{role}.Sanitize()+" NOLOGIN")
	return err
}

// Enable allows role to log in again with its existing password.
func (c *Conn) Enable(ctx context.Context, role string) error {
	_, err := c.pool.Exec(ctx, "ALTER ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN")
	return err
}

// Session is one live connection, as pg_stat_activity reports it.
type Session struct {
	Role        string    `json:"role"`
	Application string    `json:"application"`
	ClientAddr  string    `json:"client_addr"`
	Started     time.Time `json:"started"`
}

// Sessions lists live client sessions for the given roles.
func (c *Conn) Sessions(ctx context.Context, roles []string) ([]Session, error) {
	rows, err := c.pool.Query(ctx, `
		SELECT usename, coalesce(application_name, ''), coalesce(host(client_addr), ''), backend_start
		FROM pg_stat_activity
		WHERE usename = ANY($1) AND backend_type = 'client backend'
		ORDER BY usename, application_name`, roles)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Session, error) {
		var s Session
		err := r.Scan(&s.Role, &s.Application, &s.ClientAddr, &s.Started)
		return s, err
	})
}

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
