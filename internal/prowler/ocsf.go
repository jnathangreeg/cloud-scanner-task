// Package prowler reads Prowler's JSON-OCSF output into provider-neutral candidates.
//
// Generate the input with, for example:
//
//	prowler aws --checks ec2_instance_port_ssh_exposed_to_internet -M json-ocsf
//
// The format is the same for AWS, Azure and GCP, so this package has no
// cloud-specific code.
package prowler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jnathangreeg/cloud-scanner-task/internal/finding"
)

// ErrMalformed is returned (wrapped) when the input is not valid Prowler JSON-OCSF.
var ErrMalformed = errors.New("malformed Prowler JSON-OCSF")

// ocsfFinding mirrors only the OCSF Detection Finding fields this tool needs.
type ocsfFinding struct {
	StatusCode   string `json:"status_code"`
	Status       string `json:"status"` // "Suppressed" when the finding is muted in Prowler
	StatusDetail string `json:"status_detail"`
	Severity     string `json:"severity"`
	Metadata     struct {
		EventCode string `json:"event_code"` // Prowler's check ID
	} `json:"metadata"`
	Cloud struct {
		Provider string `json:"provider"`
		Region   string `json:"region"`
		Account  struct {
			UID string `json:"uid"`
		} `json:"account"`
	} `json:"cloud"`
	Resources []struct {
		UID    string `json:"uid"`
		Region string `json:"region"`
	} `json:"resources"`
}

// ReadOCSF decodes a Prowler JSON-OCSF array. Errors wrap ErrMalformed.
func ReadOCSF(r io.Reader) ([]finding.Candidate, error) {
	var raw []ocsfFinding
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: decoding: %w", ErrMalformed, err)
	}

	candidates := make([]finding.Candidate, 0, len(raw))
	for i, f := range raw {
		c, err := toCandidate(f)
		if err != nil {
			return nil, fmt.Errorf("%w: finding %d: %w", ErrMalformed, i, err)
		}
		candidates = append(candidates, c)
	}
	return candidates, nil
}

func toCandidate(f ocsfFinding) (finding.Candidate, error) {
	if len(f.Resources) == 0 {
		return finding.Candidate{}, errors.New("no resources")
	}
	if f.Metadata.EventCode == "" {
		return finding.Candidate{}, errors.New("no metadata.event_code")
	}
	region := f.Cloud.Region
	if region == "" {
		region = f.Resources[0].Region
	}
	return finding.Candidate{
		Provider:   f.Cloud.Provider,
		CheckID:    f.Metadata.EventCode,
		Status:     f.StatusCode,
		Severity:   severity(f.Severity),
		AccountID:  f.Cloud.Account.UID,
		Region:     region,
		ResourceID: f.Resources[0].UID,
		Detail:     f.StatusDetail,
		Muted:      strings.EqualFold(f.Status, "Suppressed"),
	}, nil
}

// severity maps OCSF severity names onto ours. Unknown values become info.
func severity(s string) finding.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}
