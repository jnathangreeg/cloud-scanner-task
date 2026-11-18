package aws

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/jnathangreeg/cloud-scanner-task/internal/finding"
)

// checkPorts maps the Prowler checks this verifier understands to their TCP port.
// Prowler has the same check for 15+ other ports; each is one more line here.
var checkPorts = map[string]int32{
	"ec2_instance_port_ssh_exposed_to_internet": 22,
	"ec2_instance_port_rdp_exposed_to_internet": 3389,
}

// ExposureVerifier proves or refutes "port exposed to the internet" candidates.
type ExposureVerifier struct {
	inv *Inventory
}

// NewExposureVerifier returns a verifier that reads from inv.
func NewExposureVerifier(inv *Inventory) *ExposureVerifier {
	return &ExposureVerifier{inv: inv}
}

// CheckIDs returns the Prowler check IDs this verifier handles, sorted.
func (v *ExposureVerifier) CheckIDs() []string {
	return slices.Sorted(maps.Keys(checkPorts))
}

// outcome of walking the path for one address family.
type outcome int

const (
	exposed outcome = iota
	blocked
	unknown
)

// walk is the evidence for one address family.
type walk struct {
	family  family
	outcome outcome
	steps   []finding.Step
	reason  string     // why it is blocked or unknown
	missing []string   // API actions whose data was absent
	open    []openRule // security group rules that open the port
	address string     // public address, if any
	from    string     // internet range that can reach it, if exposed
	broad   bool       // the reachable range is broad (/8 or wider for IPv4, /32 or wider for IPv6)
}

// Verify walks the network path for the candidate's instance and port.
func (v *ExposureVerifier) Verify(_ context.Context, c finding.Candidate) finding.Result {
	port, ok := checkPorts[c.CheckID]
	if !ok {
		return unknownResult(c, fmt.Sprintf("check %s is not handled by the AWS exposure verifier", c.CheckID), nil)
	}
	id := instanceID(c.ResourceID)
	if reason, ok := v.inv.Missing[ActionDescribeInstances]; ok {
		return unknownResult(c, "instance data was not collected", []string{ActionDescribeInstances + " (" + reason + ")"})
	}
	in, ok := v.inv.Instances[id]
	if !ok {
		return unknownResult(c, fmt.Sprintf("instance %s is not in the inventory snapshot", id), nil)
	}
	if in.State == nil || in.State.Name != types.InstanceStateNameRunning {
		return stoppedResult(c, in)
	}
	return decide(c, port, v.walk(in, port, ipv4), v.walk(in, port, ipv6))
}

// walk evaluates hops 2 to 5 for one family. Hop 1 (instance running) is checked by Verify.
// A hop that blocks with real data is a valid conclusion even if later data is missing.
func (v *ExposureVerifier) walk(in types.Instance, port int32, f family) walk {
	w := walk{family: f, steps: []finding.Step{{Control: "instance", Resource: awssdk.ToString(in.InstanceId), Passed: true, Detail: "running"}}}

	w, done := v.groupHop(w, in, port)
	if done {
		return w
	}
	addr, ok := publicAddress(in, f)
	if !ok {
		return w.block("public address", awssdk.ToString(in.InstanceId), "no public "+f.String()+" address")
	}
	w.address = addr
	w.pass("public address", addr, "public "+f.String())

	if w, done = v.routeHop(w, in); done {
		return w
	}
	return v.naclHop(w, in, port)
}

func (v *ExposureVerifier) groupHop(w walk, in types.Instance, port int32) (walk, bool) {
	if reason, ok := v.inv.Missing[ActionDescribeSecurityGroups]; ok {
		return w.unknown("security group data is missing", []string{ActionDescribeSecurityGroups + " (" + reason + ")"}), true
	}
	groups, absent := v.groupsOf(in)
	from := fmt.Sprintf("tcp/%d from %s", port, w.family.anywhere())
	w.open = sgOpenRules(groups, port, w.family)
	if len(w.open) == 0 && len(absent) > 0 {
		// A group we could not see might be the one that opens the port.
		return w.unknown("security groups missing from the snapshot", []string{ActionDescribeSecurityGroups + " (" + strings.Join(absent, ",") + " not in snapshot)"}), true
	}
	if len(w.open) == 0 {
		return w.block("security group", strings.Join(groupIDs(in), ","), "no security group allows "+from), true
	}
	ids := make([]string, 0, len(w.open))
	for _, r := range w.open {
		ids = append(ids, r.GroupID)
	}
	w.pass("security group", strings.Join(slices.Compact(ids), ","), "allows "+from)
	return w, false
}

func (v *ExposureVerifier) routeHop(w walk, in types.Instance) (walk, bool) {
	if reason, ok := v.inv.Missing[ActionDescribeRouteTables]; ok {
		return w.unknown("route table data is missing", []string{ActionDescribeRouteTables + " (" + reason + ")"}), true
	}
	rt, ok := routeTableFor(v.inv.RouteTables, awssdk.ToString(in.SubnetId), awssdk.ToString(in.VpcId))
	if !ok {
		return w.unknown("no route table found for subnet "+awssdk.ToString(in.SubnetId), nil), true
	}
	r, ok := internetRoute(rt, w.family)
	if !ok {
		return w.block("route table", awssdk.ToString(rt.RouteTableId), "no active route to an internet gateway for "+w.family.String()), true
	}
	dest := awssdk.ToString(r.DestinationCidrBlock)
	if w.family == ipv6 {
		dest = awssdk.ToString(r.DestinationIpv6CidrBlock)
	}
	w.pass("route table", awssdk.ToString(rt.RouteTableId), dest+" → "+awssdk.ToString(r.GatewayId))
	return w, false
}

func (v *ExposureVerifier) naclHop(w walk, in types.Instance, port int32) walk {
	if reason, ok := v.inv.Missing[ActionDescribeNetworkAcls]; ok {
		return w.unknown("network ACL data is missing", []string{ActionDescribeNetworkAcls + " (" + reason + ")"})
	}
	acl, ok := naclFor(v.inv.NetworkACLs, awssdk.ToString(in.SubnetId))
	if !ok {
		return w.unknown("no network ACL found for subnet "+awssdk.ToString(in.SubnetId), nil)
	}
	aclID := awssdk.ToString(acl.NetworkAclId)
	inbound := naclDecision(acl, port, w.family, false)
	if !inbound.Allowed {
		return w.block("network ACL", aclID, fmt.Sprintf("inbound %s denies tcp/%d from the internet", ruleName(inbound.Rule), port))
	}
	outbound := naclDecision(acl, ephemeralPort, w.family, true)
	if !outbound.Allowed {
		return w.block("network ACL", aclID, fmt.Sprintf("outbound %s denies the return traffic (tcp/%d to the internet)", ruleName(outbound.Rule), ephemeralPort))
	}
	w.pass("network ACL", aclID, fmt.Sprintf("inbound %s allows tcp/%d from %s; outbound %s allows the return traffic",
		ruleName(inbound.Rule), port, inbound.From, ruleName(outbound.Rule)))
	w.outcome, w.from = exposed, inbound.From.String()
	w.broad = inbound.From.Bits() <= map[family]int{ipv4: 8, ipv6: 32}[w.family]
	return w
}

func ruleName(rule int32) string {
	if rule >= defaultNACLRule { // AWS numbers the IPv4 "*" rule 32767 and the IPv6 one 32768
		return "default rule (*)"
	}
	return fmt.Sprintf("rule %d", rule)
}

// groupsOf resolves the instance's security groups and lists the IDs absent from the snapshot.
func (v *ExposureVerifier) groupsOf(in types.Instance) ([]types.SecurityGroup, []string) {
	var groups []types.SecurityGroup
	var absent []string
	for _, id := range groupIDs(in) {
		if g, ok := v.inv.SecurityGroups[id]; ok {
			groups = append(groups, g)
		} else {
			absent = append(absent, id)
		}
	}
	return groups, absent
}

func groupIDs(in types.Instance) []string {
	ids := make([]string, 0, len(in.SecurityGroups))
	for _, g := range in.SecurityGroups {
		ids = append(ids, awssdk.ToString(g.GroupId))
	}
	return ids
}

func (w *walk) pass(control, resource, detail string) {
	w.steps = append(w.steps, finding.Step{Control: control, Resource: resource, Passed: true, Detail: detail})
}

func (w walk) block(control, resource, detail string) walk {
	w.steps = append(w.steps, finding.Step{Control: control, Resource: resource, Passed: false, Detail: detail})
	w.outcome, w.reason = blocked, control+" "+resource+": "+detail
	return w
}

func (w walk) unknown(reason string, missing []string) walk {
	w.outcome, w.reason, w.missing = unknown, reason, missing
	return w
}

// instanceID extracts "i-0abc" from "arn:aws:ec2:region:account:instance/i-0abc".
func instanceID(resourceID string) string {
	return resourceID[strings.LastIndex(resourceID, "/")+1:]
}
