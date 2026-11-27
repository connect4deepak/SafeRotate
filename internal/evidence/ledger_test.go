package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	l := &Ledger{Path: path}
	l.Append("rot-1", "plan", map[string]any{"from_role": "app_blue", "checks": 3})
	l.Append("rot-1", "verify", map[string]any{"pass": true, "nested": map[string]any{"b": 1, "a": 2}})
	// A new Ledger (as in a new CLI run) must continue the chain.
	(&Ledger{Path: path}).Append("rot-1", "done", nil)

	entries, err := Read(path)
	if err != nil || len(entries) != 3 {
		t.Fatalf("read: %v, %d entries", err, len(entries))
	}
	if err := Check(entries); err != nil {
		t.Fatalf("untouched ledger should verify: %v", err)
	}

	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), "app_blue", "app_evil", 1)), 0o644)
	entries, _ = Read(path)
	if err := Check(entries); err == nil {
		t.Fatal("tampered ledger should fail the check")
	}
	if r := Report(entries); !strings.Contains(r, "FAILED") {
		t.Fatal("report should say integrity failed")
	}
}

func TestFingerprintHidesValue(t *testing.T) {
	f := Fingerprint("k", "s3cret")
	if strings.Contains(f, "s3cret") || f != Fingerprint("k", "s3cret") || f == Fingerprint("other", "s3cret") {
		t.Fatalf("bad fingerprint %q", f)
	}
}
