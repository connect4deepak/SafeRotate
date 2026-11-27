package evidence

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Report renders the ledger as a Markdown audit report. The chain is checked
// first and the result is stated at the top.
func Report(entries []Entry) string {
	var b strings.Builder
	b.WriteString("# SafeRotate audit report\n\n")
	if err := Check(entries); err != nil {
		fmt.Fprintf(&b, "**Ledger integrity: FAILED** (%v). Do not rely on this report.\n\n", err)
	} else if len(entries) > 0 {
		fmt.Fprintf(&b, "**Ledger integrity: verified.** %d entries, hash chain intact, last hash `%s`.\n\n", len(entries), entries[len(entries)-1].Hash)
	} else {
		b.WriteString("The ledger is empty.\n")
		return b.String()
	}
	b.WriteString("Secret values are never recorded; only keyed fingerprints (HMAC-SHA256).\n\n")

	byRot := map[string][]Entry{}
	var order []string
	for _, e := range entries {
		if _, ok := byRot[e.Rotation]; !ok {
			order = append(order, e.Rotation)
		}
		byRot[e.Rotation] = append(byRot[e.Rotation], e)
	}
	for _, id := range order {
		es := byRot[id]
		outcome := es[len(es)-1].Step
		fmt.Fprintf(&b, "## %s: %s\n\n", id, outcomeText(outcome))
		b.WriteString("| # | Time (UTC) | Step | Evidence |\n|---|---|---|---|\n")
		for _, e := range es {
			fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", e.Seq, e.Time.Format("2006-01-02 15:04:05"), e.Step, detailText(e.Detail))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func outcomeText(last string) string {
	switch last {
	case "done":
		return "rotated, old credential revoked"
	case "rollback":
		return "rolled back, nothing revoked"
	case "denied":
		return "denied by policy"
	default:
		return "incomplete (last step: " + last + ")"
	}
}

func detailText(d map[string]any) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, _ := json.Marshal(d[k])
		parts = append(parts, k+"="+strings.ReplaceAll(string(v), "|", "\\|"))
	}
	return strings.Join(parts, ", ")
}
