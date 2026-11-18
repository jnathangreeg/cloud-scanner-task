// Package finding holds the provider-neutral types shared by every stage of
// the scanner: what comes in from a check engine (Candidate) and what goes
// out after verification (Result).
package finding

// Status is the verdict for one candidate after verification.
type Status string

const (
	// StatusExposed means every hop of the path was proven open.
	StatusExposed Status = "EXPOSED"
	// StatusNotExposed means all data was present and at least one control blocks the path.
	StatusNotExposed Status = "NOT_EXPOSED"
	// StatusUnknown means data or permissions were missing, so no conclusion is possible.
	StatusUnknown Status = "UNKNOWN"
	// StatusUnverified means no verifier exists for the check; the engine's verdict is kept as-is.
	StatusUnverified Status = "UNVERIFIED"
)

// Severity of a result, aligned with Prowler's severity names.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Candidate is one failed check reported by a check engine such as Prowler.
// It is a claim that still needs to be proven.
type Candidate struct {
	Provider   string   `json:"provider"`
	CheckID    string   `json:"check_id"`
	Status     string   `json:"status"`
	Severity   Severity `json:"severity"`
	AccountID  string   `json:"account_id"`
	Region     string   `json:"region"`
	ResourceID string   `json:"resource_id"`
	Detail     string   `json:"detail"`
}

// Step is one hop of the evidence path, e.g. "security group sg-1 allows 22 from 0.0.0.0/0".
type Step struct {
	Control  string `json:"control"`
	Resource string `json:"resource"`
	Passed   bool   `json:"passed"`
	Detail   string `json:"detail"`
}

// Result is the verified outcome for one candidate.
type Result struct {
	Candidate   Candidate `json:"candidate"`
	Status      Status    `json:"status"`
	Severity    Severity  `json:"severity"`
	Summary     string    `json:"summary"`
	Path        []Step    `json:"path,omitempty"`
	Remediation []string  `json:"remediation,omitempty"`
	Missing     []string  `json:"missing,omitempty"`
}
