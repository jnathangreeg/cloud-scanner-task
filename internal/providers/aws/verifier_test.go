package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jnathangreeg/cloud-scanner-task/internal/finding"
)

const sshCheck = "ec2_instance_port_ssh_exposed_to_internet"

func instance(id, subnet, vpc, publicIP string) types.Instance {
	in := types.Instance{
		InstanceId:     awssdk.String(id),
		State:          &types.InstanceState{Name: types.InstanceStateNameRunning},
		SubnetId:       awssdk.String(subnet),
		VpcId:          awssdk.String(vpc),
		SecurityGroups: []types.GroupIdentifier{{GroupId: awssdk.String("sg-ssh")}},
	}
	if publicIP != "" {
		in.PublicIpAddress = awssdk.String(publicIP)
	}
	return in
}

func acl(id string, subnets []string, entries ...types.NetworkAclEntry) types.NetworkAcl {
	a := types.NetworkAcl{NetworkAclId: awssdk.String(id), Entries: entries}
	for _, s := range subnets {
		a.Associations = append(a.Associations, types.NetworkAclAssociation{SubnetId: awssdk.String(s)})
	}
	return a
}

// testInventory models one account: a public subnet, a subnet whose ACL denies 22,
// a private subnet, and a second VPC whose main route table has no internet route.
func testInventory() *Inventory {
	allowAll := entry(100, types.RuleActionAllow, "-1", "0.0.0.0/0", -1, -1)
	allowAllV6 := types.NetworkAclEntry{
		RuleNumber: awssdk.Int32(101), RuleAction: types.RuleActionAllow, Protocol: awssdk.String("-1"),
		Egress: awssdk.Bool(false), Ipv6CidrBlock: awssdk.String("::/0"),
	}
	deny22 := entry(90, types.RuleActionDeny, "6", "0.0.0.0/0", 22, 22)
	outAll, outAllV6 := egressOf(allowAll), egressOf(allowAllV6)
	igwV6 := types.Route{DestinationIpv6CidrBlock: awssdk.String("::/0"), GatewayId: awssdk.String("igw-1")}

	v6 := instance("i-v6", "subnet-pub", "vpc-a", "")
	v6.NetworkInterfaces = []types.InstanceNetworkInterface{
		{Ipv6Addresses: []types.InstanceIpv6Address{{Ipv6Address: awssdk.String("2001:db8::10")}}},
	}
	stopped := instance("i-stopped", "subnet-pub", "vpc-a", "")
	stopped.State = &types.InstanceState{Name: types.InstanceStateNameStopped}
	closed := instance("i-closed", "subnet-pub", "vpc-a", "203.0.113.50")
	closed.SecurityGroups = []types.GroupIdentifier{{GroupId: awssdk.String("sg-web")}}

	inv := &Inventory{
		Instances: map[string]types.Instance{
			"i-web":      instance("i-web", "subnet-pub", "vpc-a", "203.0.113.10"),
			"i-nacl":     instance("i-nacl", "subnet-locked", "vpc-a", "203.0.113.20"),
			"i-private":  instance("i-private", "subnet-priv", "vpc-a", ""),
			"i-othervpc": instance("i-othervpc", "subnet-b", "vpc-b", "203.0.113.40"),
			"i-v6":       v6,
			"i-stopped":  stopped,
			"i-closed":   closed,
		},
		SecurityGroups: map[string]types.SecurityGroup{
			"sg-ssh": group("sg-ssh", perm("tcp", 22, 22, "0.0.0.0/0", "::/0")),
			"sg-web": group("sg-web", perm("tcp", 443, 443, "0.0.0.0/0", "")),
		},
		RouteTables: []types.RouteTable{
			routeTable("rtb-pub", "vpc-a", false, []string{"subnet-pub", "subnet-locked"}, igwRoute("0.0.0.0/0"), igwV6),
			routeTable("rtb-a-main", "vpc-a", true, nil, igwRoute("0.0.0.0/0")),
			routeTable("rtb-priv", "vpc-a", false, []string{"subnet-priv"}),
			routeTable("rtb-b-main", "vpc-b", true, nil),
		},
		NetworkACLs: []types.NetworkAcl{
			acl("acl-open", []string{"subnet-pub", "subnet-priv", "subnet-b"}, allowAll, allowAllV6, outAll, outAllV6),
			acl("acl-locked", []string{"subnet-locked"}, deny22, allowAll, outAll),
		},
		Missing: map[string]string{},
	}
	return inv
}

func candidate(id string) finding.Candidate {
	return finding.Candidate{
		Provider: "aws", CheckID: sshCheck, Status: "FAIL", Severity: finding.SeverityCritical,
		ResourceID: "arn:aws:ec2:eu-west-1:123456789012:instance/" + id,
	}
}

func verify(t *testing.T, inv *Inventory, id string) finding.Result {
	t.Helper()
	return NewExposureVerifier(inv).Verify(context.Background(), candidate(id))
}

func TestVerifyExposed(t *testing.T) {
	t.Parallel()

	r := verify(t, testInventory(), "i-web")

	assert.Equal(t, finding.StatusExposed, r.Status)
	assert.Equal(t, finding.SeverityCritical, r.Severity)
	assert.Contains(t, r.Summary, "203.0.113.10")
	require.Len(t, r.Path, 5, "instance, security group, address, route, ACL")
	for _, s := range r.Path {
		assert.True(t, s.Passed, s.Control)
	}
	assert.Contains(t, r.Remediation[0], "--group-id sg-ssh --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}]'")
}

func TestVerifyBlockedByNACL(t *testing.T) {
	t.Parallel()

	r := verify(t, testInventory(), "i-nacl")

	assert.Equal(t, finding.StatusNotExposed, r.Status)
	assert.Equal(t, finding.SeverityInfo, r.Severity)
	assert.Contains(t, r.Summary, "network ACL acl-locked: inbound rule 90 denies tcp/22 from the internet")
	last := r.Path[len(r.Path)-1]
	assert.False(t, last.Passed)
	assert.Equal(t, "network ACL", last.Control)
	assert.Contains(t, r.Remediation[0], "Defense in depth: sg-ssh")
}

func TestVerifyNotExposed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id          string
		wantSummary string
	}{
		{"i-private", "no public IPv4 address"},
		{"i-othervpc", "route table rtb-b-main: no active route to an internet gateway for IPv4"},
		{"i-stopped", "the instance is stopped"},
		{"i-closed", "no security group allows tcp/22 from 0.0.0.0/0"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			t.Parallel()
			r := verify(t, testInventory(), tt.id)
			assert.Equal(t, finding.StatusNotExposed, r.Status)
			assert.Contains(t, r.Summary, tt.wantSummary)
		})
	}
}

func TestVerifyIPv6OnlyIsExposed(t *testing.T) {
	t.Parallel()

	r := verify(t, testInventory(), "i-v6")

	assert.Equal(t, finding.StatusExposed, r.Status)
	assert.Contains(t, r.Summary, "2001:db8::10 (IPv6, from ::/0)")
	assert.Contains(t, r.Remediation[0], "CidrIpv6=::/0")
}

func TestVerifyUnknownWhenDataMissing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		id          string
		mutate      func(*Inventory)
		wantMissing string
	}{
		{"ACL access denied", "i-web", func(inv *Inventory) {
			inv.Missing[ActionDescribeNetworkAcls] = "AccessDenied"
			inv.NetworkACLs = nil
		}, "ec2:DescribeNetworkAcls (AccessDenied)"},
		{"route tables not collected", "i-web", func(inv *Inventory) {
			inv.Missing[ActionDescribeRouteTables] = "not collected"
		}, "ec2:DescribeRouteTables (not collected)"},
		{"instances not collected", "i-web", func(inv *Inventory) {
			inv.Missing[ActionDescribeInstances] = "AccessDenied"
		}, "ec2:DescribeInstances (AccessDenied)"},
		{"security group not in snapshot", "i-web", func(inv *Inventory) {
			delete(inv.SecurityGroups, "sg-ssh")
		}, "ec2:DescribeSecurityGroups (sg-ssh not in snapshot)"},
		{"security groups not collected", "i-web", func(inv *Inventory) {
			inv.Missing[ActionDescribeSecurityGroups] = "AccessDenied"
		}, "ec2:DescribeSecurityGroups (AccessDenied)"},
		{"instance not in snapshot", "i-missing", func(*Inventory) {}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inv := testInventory()
			tt.mutate(inv)

			r := verify(t, inv, tt.id)

			assert.Equal(t, finding.StatusUnknown, r.Status, "missing data must never become NOT_EXPOSED")
			assert.Equal(t, finding.SeverityCritical, r.Severity, "keeps Prowler's severity")
			if tt.wantMissing != "" {
				assert.Contains(t, r.Missing, tt.wantMissing)
			}
		})
	}
}

func TestVerifyBlockedHopWinsOverLaterMissingData(t *testing.T) {
	t.Parallel()

	// The security group already blocks, so missing ACL data cannot change the answer.
	inv := testInventory()
	inv.Missing[ActionDescribeNetworkAcls] = "AccessDenied"

	r := verify(t, inv, "i-closed")
	assert.Equal(t, finding.StatusNotExposed, r.Status)
}

func TestVerifyUnhandledCheck(t *testing.T) {
	t.Parallel()

	c := candidate("i-web")
	c.CheckID = "ec2_instance_imdsv2_enabled"
	r := NewExposureVerifier(testInventory()).Verify(context.Background(), c)
	assert.Equal(t, finding.StatusUnknown, r.Status)
}

func TestCheckIDs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{
		"ec2_instance_port_rdp_exposed_to_internet",
		"ec2_instance_port_ssh_exposed_to_internet",
	}, NewExposureVerifier(&Inventory{}).CheckIDs())
}

func TestInstanceID(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "i-0abc", instanceID("arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc"))
	assert.Equal(t, "i-0abc", instanceID("i-0abc"))
}

func TestVerifyOneVisibleGroupProvesTheHop(t *testing.T) {
	t.Parallel()

	// sg-ssh opens the port; sg-gone is not in the snapshot. Security groups only add
	// allows, so the missing group cannot change the answer.
	inv := testInventory()
	web := inv.Instances["i-web"]
	web.SecurityGroups = append(web.SecurityGroups, types.GroupIdentifier{GroupId: awssdk.String("sg-gone")})
	inv.Instances["i-web"] = web

	assert.Equal(t, finding.StatusExposed, verify(t, inv, "i-web").Status)
}

func TestVerifyBothFamiliesExposed(t *testing.T) {
	t.Parallel()

	inv := testInventory()
	web := inv.Instances["i-web"]
	web.Ipv6Address = awssdk.String("2001:db8::20")
	inv.Instances["i-web"] = web

	r := verify(t, inv, "i-web")
	assert.Equal(t, finding.StatusExposed, r.Status)
	assert.Contains(t, r.Summary, "203.0.113.10 (IPv4, from 0.0.0.0/0) and 2001:db8::20 (IPv6, from ::/0)")
	require.Len(t, r.Remediation, 3, "one fix per family, plus the Session Manager advice")
	assert.Contains(t, r.Remediation[1], "CidrIpv6=::/0")
}

func TestVerifyNarrowACLAllowIsHighNotCritical(t *testing.T) {
	t.Parallel()

	inv := testInventory()
	inv.NetworkACLs[0].Entries = []types.NetworkAclEntry{
		entry(100, types.RuleActionAllow, "6", "198.51.100.0/24", 22, 22),
		entry(200, types.RuleActionDeny, "-1", "0.0.0.0/0", -1, -1),
		egressOf(entry(100, types.RuleActionAllow, "-1", "0.0.0.0/0", -1, -1)),
	}

	r := verify(t, inv, "i-web")
	assert.Equal(t, finding.StatusExposed, r.Status)
	assert.Equal(t, finding.SeverityHigh, r.Severity)
	assert.Contains(t, r.Summary, "from 198.51.100.0/24")
}

func TestVerifyReturnTrafficBlockedByOutboundACL(t *testing.T) {
	t.Parallel()

	inv := testInventory()
	inv.NetworkACLs[0].Entries = []types.NetworkAclEntry{
		entry(100, types.RuleActionAllow, "-1", "0.0.0.0/0", -1, -1),
		egressOf(entry(100, types.RuleActionAllow, "6", "0.0.0.0/0", 443, 443)),
	}

	r := verify(t, inv, "i-web")
	assert.Equal(t, finding.StatusNotExposed, r.Status)
	assert.Contains(t, r.Summary, "outbound default rule (*) denies the return traffic")
}

func TestVerifyAllTrafficRuleGetsMatchingRevoke(t *testing.T) {
	t.Parallel()

	inv := testInventory()
	inv.SecurityGroups["sg-ssh"] = group("sg-ssh", perm("-1", -1, -1, "0.0.0.0/0", ""))

	r := verify(t, inv, "i-web")
	assert.Contains(t, r.Remediation[0], "--ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'")
}
