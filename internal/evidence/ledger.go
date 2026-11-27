// Package evidence is the append-only, hash-chained audit trail of every
// rotation step. Changing or removing any past entry breaks the chain.
package evidence

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Entry struct {
	Seq      int            `json:"seq"`
	Time     time.Time      `json:"time"`
	Rotation string         `json:"rotation"`
	Step     string         `json:"step"`
	Detail   map[string]any `json:"detail,omitempty"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

func (e Entry) computeHash() string {
	e.Hash = ""
	// Canonical form: round-trip through a generic value so that key order
	// is the same before and after the entry is written and read back.
	b, _ := json.Marshal(e)
	var v any
	_ = json.Unmarshal(b, &v)
	b, _ = json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Ledger appends entries to a JSON-lines file.
type Ledger struct {
	Path string
	last Entry
	read bool
}

// Append adds one step to the ledger.
func (l *Ledger) Append(rotation, step string, detail map[string]any) (Entry, error) {
	if !l.read {
		entries, err := Read(l.Path)
		if err != nil && !os.IsNotExist(err) {
			return Entry{}, err
		}
		if len(entries) > 0 {
			l.last = entries[len(entries)-1]
		}
		l.read = true
	}
	e := Entry{Seq: l.last.Seq + 1, Time: time.Now().UTC(), Rotation: rotation, Step: step, Detail: detail, PrevHash: l.last.Hash}
	e.Hash = e.computeHash()
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return e, err
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	if _, err := f.Write(append(b, '\n')); err != nil {
		return e, err
	}
	l.last = e
	return e, f.Sync()
}

// Read loads all entries without checking them.
func Read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return out, fmt.Errorf("line %d: %w", len(out)+1, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Check verifies the hash chain and returns the first broken entry's error.
func Check(entries []Entry) error {
	prev := ""
	for i, e := range entries {
		if e.Seq != i+1 {
			return fmt.Errorf("entry %d: sequence is %d, want %d", i+1, e.Seq, i+1)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("entry %d: chain broken (prev_hash mismatch)", e.Seq)
		}
		if e.computeHash() != e.Hash {
			return fmt.Errorf("entry %d: contents were modified (hash mismatch)", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}

// Fingerprint identifies a secret value without storing it: a keyed hash.
func Fingerprint(key, value string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))[:16]
}
