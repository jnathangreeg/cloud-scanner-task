package aws

import (
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/jnathangreeg/cloud-scanner-task/internal/finding"
)

// decide combines the IPv4 and IPv6 walks: exposed on either family wins,
// then unknown, and only a fully evaluated block on both is NOT_EXPOSED.
func decide(c finding.Candidate, port int32, w4, w6 walk) finding.Result {
	var open []walk
	for _, w := range []walk{w4, w6} {
		if w.outcome == exposed {
			open = append(open, w)
		}
	}
	switch {
	case len(open) > 0:
		return exposedResult(c, port, open)
	case w4.outcome == unknown:
		return unknownResult(c, w4.reason, w4.missing)
	case w6.outcome == unknown:
		return unknownResult(c, w6.reason, w6.missing)
	default:
		return blockedResult(c, port, w4, w6)
	}
}

// exposedResult reports every exposed family and a fix for every rule that opens the port.
// Reachable from a broad range is critical; from a narrow range only (for example one office /24) it is high.
func exposedResult(c finding.Candidate, port int32, open []walk) finding.Result {
	r := finding.Result{Candidate: c, Status: finding.StatusExposed, Severity: finding.SeverityHigh}
	var where []string
	for _, w := range open {
		where = append(where, fmt.Sprintf("%s (%s, from %s)", w.address, w.family, w.from))
		r.Path = append(r.Path, w.steps...)
		if w.broad {
			r.Severity = finding.SeverityCritical
		}
		for _, rule := range w.open {
			r.Remediation = append(r.Remediation, fmt.Sprintf("Remove or narrow the %s rule on %s: %s",
				w.family.anywhere(), rule.GroupID, revokeCommand(rule, w.family)))
		}
	}
	r.Summary = fmt.Sprintf("tcp/%d is reachable from the internet at %s", port, strings.Join(where, " and "))
	r.Remediation = append(r.Remediation,
		"Prefer AWS Systems Manager Session Manager over inbound SSH/RDP, so no inbound port is needed.")
	return r
}

func blockedResult(c finding.Candidate, port int32, w4, w6 walk) finding.Result {
	r := finding.Result{
		Candidate: c,
		Status:    finding.StatusNotExposed,
		Severity:  finding.SeverityInfo,
		Summary:   fmt.Sprintf("not reachable from the internet. IPv4: %s. IPv6: %s", w4.reason, w6.reason),
		Path:      w4.steps,
	}
	for _, w := range []walk{w4, w6} {
		for _, rule := range w.open {
			r.Remediation = append(r.Remediation, fmt.Sprintf(
				"Defense in depth: %s still allows tcp/%d from %s, so one change to an address, route or network ACL would expose it: %s",
				rule.GroupID, port, w.family.anywhere(), revokeCommand(rule, w.family)))
		}
	}
	return r
}

func unknownResult(c finding.Candidate, reason string, missing []string) finding.Result {
	r := finding.Result{
		Candidate: c,
		Status:    finding.StatusUnknown,
		Severity:  c.Severity,
		Summary:   "cannot conclude: " + reason + ". Keeping Prowler's severity.",
		Missing:   missing,
	}
	if len(missing) > 0 {
		r.Remediation = []string{"Grant the scanner role the missing read-only permissions (all are in the AWS managed SecurityAudit policy) and rescan."}
	}
	return r
}

func stoppedResult(c finding.Candidate, in types.Instance) finding.Result {
	state := "unknown"
	if in.State != nil {
		state = string(in.State.Name)
	}
	return finding.Result{
		Candidate: c,
		Status:    finding.StatusNotExposed,
		Severity:  finding.SeverityInfo,
		Summary:   "not reachable now: the instance is " + state + ". It becomes exposed again when started if the path is open.",
		Path:      []finding.Step{{Control: "instance", Resource: awssdk.ToString(in.InstanceId), Passed: false, Detail: state}},
	}
}

// revokeCommand removes exactly the rule's from-anywhere range, using the rule's own protocol and ports.
func revokeCommand(rule openRule, f family) string {
	perm := "IpProtocol=" + awssdk.ToString(rule.Perm.IpProtocol)
	if rule.Perm.FromPort != nil && rule.Perm.ToPort != nil && awssdk.ToString(rule.Perm.IpProtocol) != "-1" {
		perm += fmt.Sprintf(",FromPort=%d,ToPort=%d", *rule.Perm.FromPort, *rule.Perm.ToPort)
	}
	if f == ipv6 {
		perm += ",Ipv6Ranges=[{CidrIpv6=::/0}]"
	} else {
		perm += ",IpRanges=[{CidrIp=0.0.0.0/0}]"
	}
	return fmt.Sprintf("aws ec2 revoke-security-group-ingress --group-id %s --ip-permissions '%s'", rule.GroupID, perm)
}
