package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jnathangreeg/cloud-scanner-task/internal/finding"
)

func sample() []finding.Result {
	return []finding.Result{
		{
			Candidate: finding.Candidate{CheckID: "ssh", ResourceID: "i-b", Severity: finding.SeverityCritical},
			Status:    finding.StatusNotExposed, Severity: finding.SeverityInfo,
			Summary: "blocked by network ACL acl-1 rule 90",
			Path: []finding.Step{
				{Control: "security group", Resource: "sg-1", Passed: true, Detail: "allows tcp/22"},
				{Control: "network ACL", Resource: "acl-1", Passed: false, Detail: "rule 90 denies tcp/22"},
			},
		},
		{
			Candidate: finding.Candidate{CheckID: "ssh", ResourceID: "i-a", Severity: finding.SeverityCritical},
			Status:    finding.StatusExposed, Severity: finding.SeverityCritical,
			Summary:     "tcp/22 is reachable",
			Remediation: []string{"restrict sg-1"},
		},
		{
			Candidate: finding.Candidate{CheckID: "ssh", ResourceID: "i-c", Severity: finding.SeverityHigh},
			Status:    finding.StatusUnknown, Severity: finding.SeverityHigh,
			Summary: "cannot conclude",
			Missing: []string{"ec2:DescribeNetworkAcls (AccessDenied)"},
		},
	}
}

func TestSortedPutsUrgentFirst(t *testing.T) {
	t.Parallel()

	got := Sorted(sample())
	ids := []string{got[0].Candidate.ResourceID, got[1].Candidate.ResourceID, got[2].Candidate.ResourceID}
	assert.Equal(t, []string{"i-a", "i-c", "i-b"}, ids, "EXPOSED, UNKNOWN, NOT_EXPOSED")
}

func TestText(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	require.NoError(t, Text(&buf, sample()))
	out := buf.String()

	assert.Contains(t, out, "Prowler findings verified: 3 · EXPOSED 1 · NOT_EXPOSED 1 · UNKNOWN 1 · UNVERIFIED 0")
	assert.Contains(t, out, "[EXPOSED] critical  i-a")
	assert.Contains(t, out, "✔ security group")
	assert.Contains(t, out, "✘ network ACL")
	assert.Contains(t, out, "  fix:\n    - restrict sg-1")
	assert.Contains(t, out, "  missing:\n    - ec2:DescribeNetworkAcls (AccessDenied)")
	assert.Less(t, bytes.Index(buf.Bytes(), []byte("i-a")), bytes.Index(buf.Bytes(), []byte("i-b")))
}

func TestJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	require.NoError(t, JSON(&buf, sample()))

	var got struct {
		Counts  map[string]int   `json:"counts"`
		Results []finding.Result `json:"results"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, map[string]int{"EXPOSED": 1, "NOT_EXPOSED": 1, "UNKNOWN": 1}, got.Counts)
	require.Len(t, got.Results, 3)
	assert.Equal(t, finding.StatusExposed, got.Results[0].Status)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, assert.AnError }

func TestWritersReportErrors(t *testing.T) {
	t.Parallel()

	assert.ErrorIs(t, Text(failingWriter{}, sample()), assert.AnError)
	assert.ErrorIs(t, JSON(failingWriter{}, sample()), assert.AnError)
}
