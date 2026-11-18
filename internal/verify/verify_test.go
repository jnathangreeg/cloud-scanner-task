package verify

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jnathangreeg/cloud-scanner-task/internal/finding"
)

type fakeVerifier struct{ ids []string }

func (f fakeVerifier) CheckIDs() []string { return f.ids }

func (f fakeVerifier) Verify(_ context.Context, c finding.Candidate) finding.Result {
	return finding.Result{Candidate: c, Status: finding.StatusExposed, Severity: finding.SeverityCritical}
}

func TestRegistryRun(t *testing.T) {
	t.Parallel()

	r := NewRegistry(fakeVerifier{ids: []string{"ssh"}})
	results, err := r.Run(context.Background(), []finding.Candidate{
		{CheckID: "ssh", Status: "FAIL", ResourceID: "a"},
		{CheckID: "ssh", Status: "PASS", ResourceID: "b"},
		{CheckID: "ssh", Status: "FAIL", ResourceID: "muted", Muted: true},
		{CheckID: "imds", Status: "fail", Severity: finding.SeverityMedium, ResourceID: "c", Detail: "IMDSv1 enabled"},
	})

	require.NoError(t, err)
	require.Len(t, results, 2, "PASS and muted candidates are dropped")
	assert.Equal(t, finding.StatusExposed, results[0].Status)
	assert.Equal(t, "a", results[0].Candidate.ResourceID)

	assert.Equal(t, finding.StatusUnverified, results[1].Status, "no verifier: kept, not dropped")
	assert.Equal(t, finding.SeverityMedium, results[1].Severity, "keeps the engine's severity")
	assert.Contains(t, results[1].Summary, "IMDSv1 enabled")
}

func TestRegistryRunStopsOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := NewRegistry().Run(ctx, []finding.Candidate{{CheckID: "x", Status: "FAIL"}})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, results)
}

func TestNewRegistryPanicsOnDuplicateCheck(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, `verify: check "ssh" registered twice`, func() {
		NewRegistry(fakeVerifier{ids: []string{"ssh"}}, fakeVerifier{ids: []string{"ssh"}})
	})
}
