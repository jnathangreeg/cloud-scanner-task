package prowler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jnathangreeg/cloud-scanner-task/internal/finding"
)

const twoFindings = `[
  {
    "status_code": "FAIL",
    "status_detail": "Instance i-0web has SSH exposed to 0.0.0.0/0 on public IP address 203.0.113.10 in public subnet subnet-0pub.",
    "severity": "Critical",
    "metadata": {"event_code": "ec2_instance_port_ssh_exposed_to_internet"},
    "cloud": {"provider": "aws", "region": "eu-west-1", "account": {"uid": "123456789012"}},
    "resources": [{"uid": "arn:aws:ec2:eu-west-1:123456789012:instance/i-0web", "region": "eu-west-1"}]
  },
  {
    "status_code": "PASS",
    "status_detail": "IMDSv2 is required.",
    "severity": "Informational",
    "metadata": {"event_code": "ec2_instance_imdsv2_enabled"},
    "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
    "resources": [{"uid": "arn:aws:ec2:eu-west-1:123456789012:instance/i-0web", "region": "eu-west-1"}]
  }
]`

func TestReadOCSF(t *testing.T) {
	t.Parallel()

	got, err := ReadOCSF(strings.NewReader(twoFindings))
	require.NoError(t, err)
	require.Len(t, got, 2)

	assert.Equal(t, finding.Candidate{
		Provider:   "aws",
		CheckID:    "ec2_instance_port_ssh_exposed_to_internet",
		Status:     "FAIL",
		Severity:   finding.SeverityCritical,
		AccountID:  "123456789012",
		Region:     "eu-west-1",
		ResourceID: "arn:aws:ec2:eu-west-1:123456789012:instance/i-0web",
		Detail:     "Instance i-0web has SSH exposed to 0.0.0.0/0 on public IP address 203.0.113.10 in public subnet subnet-0pub.",
	}, got[0])

	assert.Equal(t, finding.SeverityInfo, got[1].Severity, "Informational maps to info")
	assert.Equal(t, "eu-west-1", got[1].Region, "falls back to the resource region")
}

func TestReadOCSFErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "not JSON", input: `{`, wantErr: "decoding"},
		{name: "object instead of array", input: `{"status_code":"FAIL"}`, wantErr: "decoding"},
		{name: "no resources", input: `[{"status_code":"FAIL","metadata":{"event_code":"x"}}]`, wantErr: "finding 0: no resources"},
		{name: "no check id", input: `[{"status_code":"FAIL","resources":[{"uid":"r"}]}]`, wantErr: "finding 0: no metadata.event_code"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ReadOCSF(strings.NewReader(tt.input))
			require.ErrorIs(t, err, ErrMalformed)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestReadOCSFMuted(t *testing.T) {
	t.Parallel()

	got, err := ReadOCSF(strings.NewReader(`[{"status_code":"FAIL","status":"Suppressed","metadata":{"event_code":"x"},"resources":[{"uid":"r"}]}]`))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.True(t, got[0].Muted)
}

func TestReadOCSFEmpty(t *testing.T) {
	t.Parallel()

	got, err := ReadOCSF(strings.NewReader(`[]`))
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestSeverity(t *testing.T) {
	t.Parallel()

	tests := map[string]finding.Severity{
		"Critical":      finding.SeverityCritical,
		"high":          finding.SeverityHigh,
		"Medium":        finding.SeverityMedium,
		"Low":           finding.SeverityLow,
		"Informational": finding.SeverityInfo,
		"":              finding.SeverityInfo,
		"weird":         finding.SeverityInfo,
	}
	for in, want := range tests {
		assert.Equal(t, want, severity(in), in)
	}
}
