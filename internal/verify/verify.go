// Package verify is the revoke gate: the old credential may be revoked only
// after it has had zero use for a quiet window while error rates stayed normal.
package verify

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type Gate struct {
	// OldUsers returns who is still using the old credential.
	OldUsers func(context.Context) ([]string, error)
	// ErrorRate returns the current error ratio of the affected services.
	ErrorRate    func(context.Context) (float64, error)
	MaxErrorRate float64
	Quiet        time.Duration // old credential must be unused this long
	MaxWait      time.Duration // give up (and roll back) after this
	Interval     time.Duration
	Now          func() time.Time // for tests; defaults to time.Now
	Log          func(Observation)
}

type Observation struct {
	At        time.Time `json:"at"`
	OldUsers  []string  `json:"old_users"`
	ErrorRate float64   `json:"error_rate"`
}

type Result struct {
	Pass         bool          `json:"pass"`
	Reason       string        `json:"reason"`
	Observations []Observation `json:"observations"`
}

func (g Gate) Run(ctx context.Context) (Result, error) {
	now := g.Now
	if now == nil {
		now = time.Now
	}
	var res Result
	start := now()
	var quietSince time.Time
	for {
		users, err := g.OldUsers(ctx)
		if err != nil {
			return res, fmt.Errorf("usage check: %w", err)
		}
		rate, err := g.ErrorRate(ctx)
		if err != nil {
			return res, fmt.Errorf("health check: %w", err)
		}
		t := now()
		o := Observation{At: t, OldUsers: users, ErrorRate: rate}
		res.Observations = append(res.Observations, o)
		if g.Log != nil {
			g.Log(o)
		}

		if rate > g.MaxErrorRate {
			res.Reason = fmt.Sprintf("error rate %.2f%% is above the %.2f%% threshold", rate*100, g.MaxErrorRate*100)
			return res, nil
		}
		if len(users) == 0 {
			if quietSince.IsZero() {
				quietSince = t
			}
			if t.Sub(quietSince) >= g.Quiet {
				res.Pass = true
				res.Reason = fmt.Sprintf("old credential unused for %s and error rate %.2f%%", g.Quiet, rate*100)
				return res, nil
			}
		} else {
			quietSince = time.Time{}
		}
		if t.Sub(start) >= g.MaxWait {
			res.Reason = fmt.Sprintf("old credential still in use after %s by: %s", g.MaxWait, strings.Join(users, ", "))
			if len(users) == 0 {
				res.Reason = fmt.Sprintf("old credential not quiet for %s within %s", g.Quiet, g.MaxWait)
			}
			return res, nil
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(g.Interval):
		}
	}
}
