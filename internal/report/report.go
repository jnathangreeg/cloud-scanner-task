// Package report renders verification results for people (text) and machines (JSON).
package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/jnathangreeg/cloud-scanner-task/internal/finding"
)

// statusOrder puts what needs action first.
var statusOrder = map[finding.Status]int{
	finding.StatusExposed:    0,
	finding.StatusUnknown:    1,
	finding.StatusUnverified: 2,
	finding.StatusNotExposed: 3,
}

// Sorted returns the results ordered by status (most urgent first), then resource.
func Sorted(results []finding.Result) []finding.Result {
	out := slices.Clone(results)
	slices.SortStableFunc(out, func(a, b finding.Result) int {
		return cmp.Or(
			cmp.Compare(statusOrder[a.Status], statusOrder[b.Status]),
			cmp.Compare(a.Candidate.ResourceID, b.Candidate.ResourceID),
		)
	})
	return out
}

// Counts returns how many results have each status.
func Counts(results []finding.Result) map[finding.Status]int {
	counts := map[finding.Status]int{}
	for _, r := range results {
		counts[r.Status]++
	}
	return counts
}

// JSON writes {"counts": ..., "results": [...]} with results sorted.
func JSON(w io.Writer, results []finding.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	err := enc.Encode(struct {
		Counts  map[finding.Status]int `json:"counts"`
		Results []finding.Result       `json:"results"`
	}{Counts(results), Sorted(results)})
	if err != nil {
		return fmt.Errorf("writing JSON report: %w", err)
	}
	return nil
}

// Text writes a human-readable report: a summary line, then one block per result
// with the evidence path as a checklist, the fix and any missing data.
func Text(w io.Writer, results []finding.Result) error {
	var b strings.Builder
	b.WriteString(summaryLine(results))
	for _, r := range Sorted(results) {
		writeResult(&b, r)
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("writing text report: %w", err)
	}
	return nil
}

func summaryLine(results []finding.Result) string {
	c := Counts(results)
	return fmt.Sprintf("Prowler findings verified: %d · EXPOSED %d · NOT_EXPOSED %d · UNKNOWN %d · UNVERIFIED %d\n",
		len(results), c[finding.StatusExposed], c[finding.StatusNotExposed], c[finding.StatusUnknown], c[finding.StatusUnverified])
}

func writeResult(b *strings.Builder, r finding.Result) {
	c := r.Candidate
	fmt.Fprintf(b, "\n[%s] %s  %s\n", r.Status, r.Severity, c.ResourceID)
	fmt.Fprintf(b, "  check: %s (Prowler said %s)\n", c.CheckID, c.Severity)
	fmt.Fprintf(b, "  %s\n", r.Summary)

	if len(r.Path) > 0 {
		tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
		for _, s := range r.Path {
			mark := "✔"
			if !s.Passed {
				mark = "✘"
			}
			_, _ = fmt.Fprintf(tw, "    %s %s\t%s\t%s\n", mark, s.Control, s.Resource, s.Detail) // buffered in memory
		}
		_ = tw.Flush() // writes to a strings.Builder, which cannot fail
	}
	writeList(b, "fix", r.Remediation)
	writeList(b, "missing", r.Missing)
}

func writeList(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s:\n", title)
	for _, it := range items {
		fmt.Fprintf(b, "    - %s\n", it)
	}
}
