package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Runs against a real Postgres loaded with deploy/postgres/init.sql.
// Set PG_TEST_URL to the saferotate admin URL, e.g.
// postgres://saferotate:saferotate-demo-pw@localhost/demo?sslmode=disable
func TestRolesAndSessions(t *testing.T) {
	url := os.Getenv("PG_TEST_URL")
	if url == "" {
		t.Skip("PG_TEST_URL not set")
	}
	ctx := context.Background()
	c, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.EnableWithPassword(ctx, "app_green", "it's-new"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := pgx.ParseConfig(url)
	cfg.User, cfg.Password = "app_green", "it's-new"
	cfg.RuntimeParams["application_name"] = "test-app"
	app, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("login with new password: %v", err)
	}
	ss, err := c.Sessions(ctx, []string{"app_green"})
	if err != nil || len(ss) != 1 || ss[0].Application != "test-app" {
		t.Fatalf("sessions %+v %v", ss, err)
	}
	app.Close(ctx)
	if err := c.Disable(ctx, "app_green"); err != nil {
		t.Fatal(err)
	}
	if _, err := pgx.ConnectConfig(ctx, cfg); err == nil {
		t.Fatal("NOLOGIN role should not log in")
	}
}
