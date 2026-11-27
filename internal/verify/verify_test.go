package verify

import (
	"context"
	"testing"
	"time"
)

// fakeClock advances by step on every call so tests never sleep for real.
func fakeClock(step time.Duration) func() time.Time {
	t := time.Unix(0, 0)
	return func() time.Time { t = t.Add(step); return t }
}

func gate(users [][]string, rates []float64) Gate {
	i, j := 0, 0
	return Gate{
		OldUsers: func(context.Context) ([]string, error) {
			u := users[min(i, len(users)-1)]
			i++
			return u, nil
		},
		ErrorRate: func(context.Context) (float64, error) {
			r := rates[min(j, len(rates)-1)]
			j++
			return r, nil
		},
		MaxErrorRate: 0.01,
		Quiet:        10 * time.Second,
		MaxWait:      60 * time.Second,
		Now:          fakeClock(5 * time.Second),
	}
}

func TestPassesAfterQuietWindow(t *testing.T) {
	g := gate([][]string{{"app1"}, {"app1"}, {}, {}, {}}, []float64{0})
	res, err := g.Run(context.Background())
	if err != nil || !res.Pass {
		t.Fatalf("want pass, got %+v %v", res, err)
	}
}

func TestQuietWindowRestartsWhenOldKeyIsUsedAgain(t *testing.T) {
	g := gate([][]string{{}, {"app1"}, {}, {}, {}}, []float64{0})
	res, _ := g.Run(context.Background())
	if !res.Pass || len(res.Observations) != 5 {
		t.Fatalf("want pass after 5 checks, got %d checks %+v", len(res.Observations), res)
	}
}

func TestBlocksWhenOldKeyStillUsed(t *testing.T) {
	g := gate([][]string{{"app-stale"}}, []float64{0})
	res, err := g.Run(context.Background())
	if err != nil || res.Pass {
		t.Fatalf("want block, got %+v %v", res, err)
	}
	if want := "app-stale"; !contains(res.Reason, want) {
		t.Fatalf("reason %q should name %q", res.Reason, want)
	}
}

func TestFailsOnErrorSpike(t *testing.T) {
	g := gate([][]string{{}}, []float64{0, 0.2})
	res, _ := g.Run(context.Background())
	if res.Pass || len(res.Observations) != 2 {
		t.Fatalf("want fail on second check, got %+v", res)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
