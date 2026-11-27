// Command saferotate rotates a Postgres credential without breaking the apps
// that use it, and writes evidence of every step for auditors.
//
//	saferotate discover   who is using each role right now
//	saferotate plan       what a rotation would do (dry run)
//	saferotate rotate     run the rotation: create, propagate, verify, revoke
//	saferotate report     render the audit report from the evidence ledger
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/connect4deepak/SafeRotate/internal/evidence"
	"github.com/connect4deepak/SafeRotate/internal/health"
	"github.com/connect4deepak/SafeRotate/internal/postgres"
	"github.com/connect4deepak/SafeRotate/internal/rotation"
	"github.com/connect4deepak/SafeRotate/internal/store"
	"github.com/connect4deepak/SafeRotate/internal/verify"
)

const usage = `usage: saferotate <discover|plan|rotate|report> [flags]

Run "saferotate <command> -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	switch os.Args[1] {
	case "discover":
		err = discover(ctx, os.Args[2:])
	case "plan":
		err = plan(os.Args[2:])
	case "rotate":
		err = rotate(ctx, os.Args[2:])
	case "report":
		err = report(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if errors.Is(err, rotation.ErrRolledBack) {
			os.Exit(3)
		}
		os.Exit(1)
	}
}

// common flags
type config struct {
	dbURL, secretFile, roles, target, env, ledger string
}

func flags(name string, c *config) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.StringVar(&c.dbURL, "db", os.Getenv("SAFEROTATE_DB_URL"), "admin connection URL for the target Postgres (env SAFEROTATE_DB_URL)")
	fs.StringVar(&c.secretFile, "secret-file", env("SAFEROTATE_SECRET_FILE", "/secrets/db.json"), "credential file the apps read")
	fs.StringVar(&c.roles, "roles", "app_blue,app_green", "the two login roles used for blue/green rotation")
	fs.StringVar(&c.target, "target", "db/app", "name of the secret, for the evidence")
	fs.StringVar(&c.env, "env", "production", "environment of the target, used by policy")
	fs.StringVar(&c.ledger, "ledger", env("SAFEROTATE_LEDGER", "evidence/ledger.jsonl"), "evidence ledger file")
	return fs
}

func (c config) roleList() ([2]string, error) {
	r := strings.Split(c.roles, ",")
	if len(r) != 2 || r[0] == "" || r[1] == "" || r[0] == r[1] {
		return [2]string{}, fmt.Errorf("--roles needs two different roles, got %q", c.roles)
	}
	return [2]string{r[0], r[1]}, nil
}

func discover(ctx context.Context, args []string) error {
	var c config
	flags("discover", &c).Parse(args)
	roles, err := c.roleList()
	if err != nil {
		return err
	}
	db, err := postgres.Connect(ctx, c.dbURL)
	if err != nil {
		return err
	}
	defer db.Close()
	sessions, err := db.Sessions(ctx, roles[:])
	if err != nil {
		return err
	}
	total := map[string]int{}
	counts := map[string]map[string]int{}
	for _, s := range sessions {
		if counts[s.Role] == nil {
			counts[s.Role] = map[string]int{}
		}
		counts[s.Role][s.Application]++
		total[s.Role]++
	}
	cur, err := store.File{Path: c.secretFile}.Read()
	if err == nil {
		fmt.Printf("store %s points to role %s\n", c.secretFile, cur.Username)
	}
	for _, r := range roles {
		fmt.Printf("role %s: %d session(s)\n", r, total[r])
		for app, n := range counts[r] {
			fmt.Printf("  %-20s %d\n", app, n)
		}
	}
	return nil
}

func plan(args []string) error {
	var c config
	flags("plan", &c).Parse(args)
	roles, err := c.roleList()
	if err != nil {
		return err
	}
	p, _, err := rotation.MakePlan(store.File{Path: c.secretFile}, rotation.Options{Target: c.target, Roles: roles, Env: c.env})
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	fmt.Println(string(b))
	fmt.Printf("steps: set new password on %s, point the store at %s, wait until %s has no sessions and errors are normal, then set %s NOLOGIN\n",
		p.To, p.To, p.From, p.From)
	if err := rotation.Policy(p, false); err != nil {
		fmt.Println("note:", err)
	}
	return nil
}

func rotate(ctx context.Context, args []string) error {
	var c config
	fs := flags("rotate", &c)
	approve := fs.Bool("approve", false, "approve the rotation (required for production)")
	promURL := fs.String("prometheus", env("SAFEROTATE_PROMETHEUS_URL", "http://prometheus:9090"), "Prometheus URL")
	query := fs.String("error-query", `sum(rate(demo_http_requests_total{code=~"5.."}[15s])) / sum(rate(demo_http_requests_total[15s]))`, "PromQL that returns the error ratio")
	maxErr := fs.Float64("max-error-rate", 0.01, "roll back if the error ratio goes above this")
	quiet := fs.Duration("quiet", 15*time.Second, "old credential must have zero sessions for this long")
	maxWait := fs.Duration("max-wait", 90*time.Second, "roll back if the old credential is still used after this")
	fs.Parse(args)
	roles, err := c.roleList()
	if err != nil {
		return err
	}
	key := os.Getenv("SAFEROTATE_FINGERPRINT_KEY")
	if key == "" {
		return errors.New("SAFEROTATE_FINGERPRINT_KEY must be set (key for fingerprinting secrets in the evidence)")
	}
	db, err := postgres.Connect(ctx, c.dbURL)
	if err != nil {
		return err
	}
	defer db.Close()
	prom := health.Prometheus{URL: *promURL, Query: *query}

	opts := rotation.Options{
		Target: c.target, Roles: roles, Env: c.env, Approved: *approve, FingerprintKey: key,
		NewGate: func(oldRole string) verify.Gate {
			return verify.Gate{
				OldUsers: func(ctx context.Context) ([]string, error) {
					ss, err := db.Sessions(ctx, []string{oldRole})
					users := make([]string, 0, len(ss))
					for _, s := range ss {
						users = append(users, s.Application)
					}
					return users, err
				},
				ErrorRate:    prom.ErrorRate,
				MaxErrorRate: *maxErr,
				Quiet:        *quiet,
				MaxWait:      *maxWait,
				Interval:     2 * time.Second,
			}
		},
		Logf: func(f string, a ...any) { fmt.Printf(time.Now().Format("15:04:05")+" "+f+"\n", a...) },
	}
	id, err := rotation.Rotate(ctx, db, store.File{Path: c.secretFile}, &evidence.Ledger{Path: c.ledger}, opts)
	if err != nil {
		return fmt.Errorf("%s: %w", id, err)
	}
	fmt.Printf("%s: rotated %s, evidence in %s\n", id, c.target, c.ledger)
	return nil
}

func report(args []string) error {
	var c config
	fs := flags("report", &c)
	out := fs.String("o", "", "write the report to this file instead of stdout")
	fs.Parse(args)
	entries, err := evidence.Read(c.ledger)
	if err != nil {
		return err
	}
	r := evidence.Report(entries)
	if *out != "" {
		if err := os.WriteFile(*out, []byte(r), 0o644); err != nil {
			return err
		}
	} else {
		fmt.Print(r)
	}
	return evidence.Check(entries)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
