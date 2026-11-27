// Package rotation runs one safe rotation of a Postgres credential using the
// blue/green role pattern: create new, propagate, verify, then revoke old.
// Any failure after the new credential is propagated rolls back.
package rotation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/connect4deepak/SafeRotate/internal/evidence"
	"github.com/connect4deepak/SafeRotate/internal/store"
	"github.com/connect4deepak/SafeRotate/internal/verify"
)

// DB is the part of the Postgres connector the engine needs.
type DB interface {
	EnableWithPassword(ctx context.Context, role, password string) error
	Enable(ctx context.Context, role string) error
	Disable(ctx context.Context, role string) error
}

// Store is where apps read the current credential.
type Store interface {
	Read() (store.Credential, error)
	Write(store.Credential) error
}

type Ledger interface {
	Append(rotation, step string, detail map[string]any) (evidence.Entry, error)
}

type Options struct {
	Target         string    // e.g. "db/app", used in the evidence
	Roles          [2]string // the blue/green login roles
	Env            string
	Approved       bool
	FingerprintKey string
	// NewGate builds the revoke gate for the old role.
	NewGate func(oldRole string) verify.Gate
	Logf    func(format string, args ...any)
}

var ErrRolledBack = errors.New("rotation rolled back")

// Plan describes what a rotation will do, without doing it.
type Plan struct {
	Target string `json:"target"`
	From   string `json:"from_role"`
	To     string `json:"to_role"`
	Env    string `json:"env"`
}

func MakePlan(s Store, o Options) (Plan, store.Credential, error) {
	cur, err := s.Read()
	if err != nil {
		return Plan{}, cur, fmt.Errorf("read current credential: %w", err)
	}
	var next string
	switch cur.Username {
	case o.Roles[0]:
		next = o.Roles[1]
	case o.Roles[1]:
		next = o.Roles[0]
	default:
		return Plan{}, cur, fmt.Errorf("current user %q is neither %s nor %s", cur.Username, o.Roles[0], o.Roles[1])
	}
	return Plan{Target: o.Target, From: cur.Username, To: next, Env: o.Env}, cur, nil
}

// Policy is the MVP rule set: production rotations need explicit approval.
func Policy(p Plan, approved bool) error {
	if p.Env == "production" && !approved {
		return errors.New("policy: production rotations need approval (pass --approve)")
	}
	return nil
}

// Rotate runs the whole rotation and returns its id.
func Rotate(ctx context.Context, db DB, s Store, l Ledger, o Options) (string, error) {
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	id := "rot-" + time.Now().UTC().Format("20060102T150405Z")
	rec := func(step string, d map[string]any) error {
		_, err := l.Append(id, step, d)
		return err
	}

	plan, cur, err := MakePlan(s, o)
	if err != nil {
		return id, err
	}
	logf("plan: %s from %s to %s (%s)", plan.Target, plan.From, plan.To, plan.Env)
	if err := rec("plan", map[string]any{"target": plan.Target, "from_role": plan.From, "to_role": plan.To, "env": plan.Env,
		"old_fingerprint": evidence.Fingerprint(o.FingerprintKey, cur.Password)}); err != nil {
		return id, err
	}
	if err := Policy(plan, o.Approved); err != nil {
		_ = rec("denied", map[string]any{"reason": err.Error()})
		return id, err
	}
	_ = rec("approved", map[string]any{"approved": o.Approved, "env": plan.Env})

	pw, err := newPassword()
	if err != nil {
		return id, err
	}
	if err := db.EnableWithPassword(ctx, plan.To, pw); err != nil {
		return id, fmt.Errorf("create new credential: %w", err)
	}
	logf("create: new password set on %s", plan.To)
	if err := rec("create_new", map[string]any{"role": plan.To, "fingerprint": evidence.Fingerprint(o.FingerprintKey, pw)}); err != nil {
		return id, err
	}

	if err := s.Write(store.Credential{Username: plan.To, Password: pw}); err != nil {
		return id, rollback(ctx, db, s, rec, logf, cur, plan, "propagate failed: "+err.Error())
	}
	logf("propagate: store now points to %s", plan.To)
	_ = rec("propagate", map[string]any{"store": "file", "role": plan.To})

	gate := o.NewGate(plan.From)
	gate.Log = func(ob verify.Observation) {
		logf("verify: %d session(s) on %s %v, error rate %.2f%%", len(ob.OldUsers), plan.From, ob.OldUsers, ob.ErrorRate*100)
	}
	res, err := gate.Run(ctx)
	if err != nil {
		return id, rollback(ctx, db, s, rec, logf, cur, plan, "verify error: "+err.Error())
	}
	_ = rec("verify", map[string]any{"pass": res.Pass, "reason": res.Reason, "checks": len(res.Observations),
		"quiet_window": gate.Quiet.String(), "max_error_rate": gate.MaxErrorRate})
	if !res.Pass {
		return id, rollback(ctx, db, s, rec, logf, cur, plan, res.Reason)
	}
	logf("verify: pass (%s)", res.Reason)

	if err := db.Disable(ctx, plan.From); err != nil {
		return id, fmt.Errorf("revoke old credential: %w", err)
	}
	logf("revoke: %s set to NOLOGIN", plan.From)
	if err := rec("revoke_old", map[string]any{"role": plan.From, "method": "NOLOGIN"}); err != nil {
		return id, err
	}
	return id, rec("done", map[string]any{"result": "rotated"})
}

func rollback(ctx context.Context, db DB, s Store, rec func(string, map[string]any) error,
	logf func(string, ...any), cur store.Credential, plan Plan, reason string) error {
	logf("rollback: %s", reason)
	var errs []error
	if err := db.Enable(ctx, plan.From); err != nil {
		errs = append(errs, err)
	}
	if err := s.Write(cur); err != nil {
		errs = append(errs, err)
	}
	if err := db.Disable(ctx, plan.To); err != nil {
		errs = append(errs, err)
	}
	d := map[string]any{"reason": reason, "restored_role": plan.From, "disabled_role": plan.To}
	if len(errs) > 0 {
		d["errors"] = errors.Join(errs...).Error()
	}
	_ = rec("rollback", d)
	if len(errs) > 0 {
		return fmt.Errorf("%w with errors: %v (reason: %s)", ErrRolledBack, errors.Join(errs...), reason)
	}
	return fmt.Errorf("%w: %s", ErrRolledBack, reason)
}

func newPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
