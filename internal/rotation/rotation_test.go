package rotation

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/connect4deepak/SafeRotate/internal/evidence"
	"github.com/connect4deepak/SafeRotate/internal/store"
	"github.com/connect4deepak/SafeRotate/internal/verify"
)

type fakeDB struct{ login map[string]bool }

func (f *fakeDB) EnableWithPassword(_ context.Context, r, _ string) error {
	f.login[r] = true
	return nil
}
func (f *fakeDB) Enable(_ context.Context, r string) error  { f.login[r] = true; return nil }
func (f *fakeDB) Disable(_ context.Context, r string) error { f.login[r] = false; return nil }

func setup(t *testing.T, oldUsers []string) (*fakeDB, store.File, *evidence.Ledger, Options) {
	dir := t.TempDir()
	s := store.File{Path: filepath.Join(dir, "db.json")}
	s.Write(store.Credential{Username: "app_blue", Password: "old"})
	db := &fakeDB{login: map[string]bool{"app_blue": true}}
	o := Options{
		Target: "db/app", Roles: [2]string{"app_blue", "app_green"}, Env: "production", Approved: true, FingerprintKey: "k",
		NewGate: func(string) verify.Gate {
			return verify.Gate{
				OldUsers:     func(context.Context) ([]string, error) { return oldUsers, nil },
				ErrorRate:    func(context.Context) (float64, error) { return 0, nil },
				MaxErrorRate: 0.01, Quiet: 0, MaxWait: 0, Interval: time.Millisecond,
			}
		},
	}
	return db, s, &evidence.Ledger{Path: filepath.Join(dir, "ledger.jsonl")}, o
}

func steps(t *testing.T, l *evidence.Ledger) []string {
	es, err := evidence.Read(l.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.Check(es); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Step)
	}
	return out
}

func TestRotateRevokesOldWhenUnused(t *testing.T) {
	db, s, l, o := setup(t, nil)
	if _, err := Rotate(context.Background(), db, s, l, o); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Read()
	if c.Username != "app_green" || c.Password == "old" || db.login["app_blue"] || !db.login["app_green"] {
		t.Fatalf("bad end state: %+v %v", c, db.login)
	}
	want := []string{"plan", "approved", "create_new", "propagate", "verify", "revoke_old", "done"}
	if got := steps(t, l); len(got) != len(want) || got[len(got)-1] != "done" {
		t.Fatalf("steps %v, want %v", got, want)
	}
}

func TestRotateRollsBackWhenOldStillUsed(t *testing.T) {
	db, s, l, o := setup(t, []string{"app-stale"})
	_, err := Rotate(context.Background(), db, s, l, o)
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("want rollback, got %v", err)
	}
	c, _ := s.Read()
	if c.Username != "app_blue" || c.Password != "old" || !db.login["app_blue"] || db.login["app_green"] {
		t.Fatalf("not restored: %+v %v", c, db.login)
	}
	if got := steps(t, l); got[len(got)-1] != "rollback" {
		t.Fatalf("last step %v", got)
	}
}

func TestProductionNeedsApproval(t *testing.T) {
	db, s, l, o := setup(t, nil)
	o.Approved = false
	if _, err := Rotate(context.Background(), db, s, l, o); err == nil {
		t.Fatal("want policy denial")
	}
	if c, _ := s.Read(); c.Username != "app_blue" {
		t.Fatal("store must be untouched")
	}
}
