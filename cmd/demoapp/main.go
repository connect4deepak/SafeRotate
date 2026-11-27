// Command demoapp is a small service that reads its Postgres credential from
// a file and reloads it when the file changes, the way a well-behaved app
// picks up a rotated secret. Set RELOAD=false to simulate an app that never
// reloads (the verifier must then block the revoke).
package main

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/connect4deepak/SafeRotate/internal/store"
)

type app struct {
	name    string
	dbHost  string
	dbName  string
	pool    atomic.Pointer[pgxpool.Pool]
	user    atomic.Value // string
	mu      sync.Mutex
	counts  map[int]int64
	failPct atomic.Int64 // injected error percentage, for the rollback demo
}

func main() {
	host, _ := os.Hostname()
	a := &app{
		name:   env("APP_NAME", host),
		dbHost: env("DB_HOST", "postgres"),
		dbName: env("DB_NAME", "demo"),
		counts: map[int]int64{},
	}
	secrets := store.File{Path: env("SECRET_FILE", "/secrets/db.json")}
	reload := env("RELOAD", "true") == "true"

	ctx := context.Background()
	var last store.Credential
	for {
		c, err := secrets.Read()
		if err == nil {
			if err = a.connect(ctx, c); err == nil {
				last = c
				break
			}
		}
		log.Printf("waiting for database: %v", err)
		time.Sleep(time.Second)
	}
	if reload {
		go func() {
			for range time.Tick(time.Second) {
				c, err := secrets.Read()
				if err != nil || c == last {
					continue
				}
				if err := a.connect(ctx, c); err != nil {
					log.Printf("new credential for %s does not work yet, keeping the old one: %v", c.Username, err)
					continue
				}
				last = c
			}
		}()
	}

	http.HandleFunc("/", a.handle)
	http.HandleFunc("/metrics", a.metrics)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	http.HandleFunc("/chaos", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("fail_percent"))
		a.failPct.Store(int64(n))
		fmt.Fprintf(w, "fail_percent=%d\n", n)
	})
	addr := env("ADDR", ":8080")
	log.Printf("%s listening on %s (reload=%v)", a.name, addr, reload)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// connect opens a pool with the credential and swaps it in. The old pool is
// closed after a grace period so in-flight requests finish on it.
func (a *app) connect(ctx context.Context, c store.Credential) error {
	cfg, err := pgxpool.ParseConfig(fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		url.PathEscape(c.Username), url.PathEscape(c.Password), a.dbHost, a.dbName))
	if err != nil {
		return err
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = a.name
	cfg.MaxConns = 4
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return err
	}
	old := a.pool.Swap(p)
	a.user.Store(c.Username)
	log.Printf("now using role %s", c.Username)
	if old != nil {
		go func() {
			time.Sleep(2 * time.Second)
			old.Close()
		}()
	}
	return nil
}

func (a *app) handle(w http.ResponseWriter, r *http.Request) {
	code := http.StatusOK
	defer func() { a.count(code) }()
	if rand.IntN(100) < int(a.failPct.Load()) {
		code = http.StatusInternalServerError
		http.Error(w, "injected failure", code)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	var n int
	if err := a.pool.Load().QueryRow(ctx, "SELECT count(*) FROM items").Scan(&n); err != nil {
		code = http.StatusInternalServerError
		http.Error(w, err.Error(), code)
		return
	}
	fmt.Fprintf(w, "%s: %d items (as %s)\n", a.name, n, a.user.Load())
}

func (a *app) count(code int) {
	a.mu.Lock()
	a.counts[code]++
	a.mu.Unlock()
}

func (a *app) metrics(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fmt.Fprintln(w, "# TYPE demo_http_requests_total counter")
	for _, code := range []int{200, 500} {
		fmt.Fprintf(w, "demo_http_requests_total{code=\"%d\"} %d\n", code, a.counts[code])
	}
	fmt.Fprintln(w, "# TYPE demo_db_role gauge")
	fmt.Fprintf(w, "demo_db_role{role=%q} 1\n", a.user.Load())
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
