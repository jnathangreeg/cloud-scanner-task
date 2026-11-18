// Package verify routes each candidate to the verifier that owns its check.
// It is the only place that knows several providers may exist.
package verify

import (
	"context"
	"fmt"
	"strings"

	"github.com/jnathangreeg/cloud-scanner-task/internal/finding"
)

// Verifier proves or refutes candidates for the check IDs it owns.
type Verifier interface {
	CheckIDs() []string
	Verify(ctx context.Context, c finding.Candidate) finding.Result
}

// Registry maps check IDs to verifiers.
type Registry struct {
	byCheck map[string]Verifier
}

// NewRegistry registers the verifiers. Two verifiers claiming the same check ID
// is a programming error, so it panics.
func NewRegistry(verifiers ...Verifier) *Registry {
	r := &Registry{byCheck: map[string]Verifier{}}
	for _, v := range verifiers {
		for _, id := range v.CheckIDs() {
			if _, dup := r.byCheck[id]; dup {
				panic(fmt.Sprintf("verify: check %q registered twice", id))
			}
			r.byCheck[id] = v
		}
	}
	return r
}

// Run verifies every failed candidate. Passed and muted candidates are dropped. A
// candidate without a verifier is kept as UNVERIFIED with the engine's severity,
// so nothing is silently lost. If ctx is cancelled, Run stops and returns the
// partial results with an error, so callers never mistake them for a full run.
func (r *Registry) Run(ctx context.Context, candidates []finding.Candidate) ([]finding.Result, error) {
	results := make([]finding.Result, 0, len(candidates))
	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			return results, fmt.Errorf("verification interrupted: %w", err)
		}
		if !strings.EqualFold(c.Status, "FAIL") || c.Muted {
			continue
		}
		v, ok := r.byCheck[c.CheckID]
		if !ok {
			results = append(results, unverified(c))
			continue
		}
		results = append(results, v.Verify(ctx, c))
	}
	return results, nil
}

func unverified(c finding.Candidate) finding.Result {
	return finding.Result{
		Candidate: c,
		Status:    finding.StatusUnverified,
		Severity:  c.Severity,
		Summary:   "no verifier for this check yet; Prowler's verdict is kept: " + c.Detail,
	}
}
