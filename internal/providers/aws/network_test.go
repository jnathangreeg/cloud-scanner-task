package aws

import (
	"net/netip"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
)

func perm(protocol string, from, to int32, v4, v6 string) types.IpPermission {
	p := types.IpPermission{IpProtocol: awssdk.String(protocol), FromPort: awssdk.Int32(from), ToPort: awssdk.Int32(to)}
	if v4 != "" {
		p.IpRanges = []types.IpRange{{CidrIp: awssdk.String(v4)}}
	}
	if v6 != "" {
		p.Ipv6Ranges = []types.Ipv6Range{{CidrIpv6: awssdk.String(v6)}}
	}
	return p
}

func group(id string, perms ...types.IpPermission) types.SecurityGroup {
	return types.SecurityGroup{GroupId: awssdk.String(id), IpPermissions: perms}
}

func TestSecurityGroupOpenRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		perm   types.IpPermission
		family family
		want   bool
	}{
		{"exact port from anywhere", perm("tcp", 22, 22, "0.0.0.0/0", ""), ipv4, true},
		{"all traffic", perm("-1", -1, -1, "0.0.0.0/0", ""), ipv4, true},
		{"port inside a range", perm("tcp", 0, 65535, "0.0.0.0/0", ""), ipv4, true},
		{"protocol as number", perm("6", 22, 22, "0.0.0.0/0", ""), ipv4, true},
		{"other port", perm("tcp", 80, 80, "0.0.0.0/0", ""), ipv4, false},
		{"udp is not tcp", perm("udp", 22, 22, "0.0.0.0/0", ""), ipv4, false},
		{"private range", perm("tcp", 22, 22, "10.0.0.0/8", ""), ipv4, false},
		{"IPv6 rule, IPv6 family", perm("tcp", 22, 22, "", "::/0"), ipv6, true},
		{"IPv6 rule, IPv4 family", perm("tcp", 22, 22, "", "::/0"), ipv4, false},
		{"IPv4 rule, IPv6 family", perm("tcp", 22, 22, "0.0.0.0/0", ""), ipv6, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			open := sgOpenRules([]types.SecurityGroup{group("sg-1", tt.perm)}, 22, tt.family)
			assert.Equal(t, tt.want, len(open) == 1)
		})
	}
}

func TestSecurityGroupOpenRulesReturnsEveryOpeningRule(t *testing.T) {
	t.Parallel()

	groups := []types.SecurityGroup{
		group("sg-web", perm("tcp", 443, 443, "0.0.0.0/0", "")),
		group("sg-ssh", perm("tcp", 22, 22, "0.0.0.0/0", "")),
		group("sg-all", perm("-1", -1, -1, "0.0.0.0/0", "")),
	}
	open := sgOpenRules(groups, 22, ipv4)
	if assert.Len(t, open, 2) {
		assert.Equal(t, "sg-ssh", open[0].GroupID)
		assert.Equal(t, "sg-all", open[1].GroupID)
	}
}

func TestPublicAddress(t *testing.T) {
	t.Parallel()

	v4 := types.Instance{PublicIpAddress: awssdk.String("203.0.113.10")}
	v6 := types.Instance{NetworkInterfaces: []types.InstanceNetworkInterface{
		{Ipv6Addresses: []types.InstanceIpv6Address{{Ipv6Address: awssdk.String("2001:db8::10")}}},
	}}
	private := types.Instance{PrivateIpAddress: awssdk.String("10.0.1.5")}

	ip, ok := publicAddress(v4, ipv4)
	assert.True(t, ok)
	assert.Equal(t, "203.0.113.10", ip)

	ip, ok = publicAddress(v6, ipv6)
	assert.True(t, ok)
	assert.Equal(t, "2001:db8::10", ip)

	_, ok = publicAddress(v6, ipv4)
	assert.False(t, ok, "an IPv6 address is not a public IPv4")
	_, ok = publicAddress(private, ipv4)
	assert.False(t, ok)
	_, ok = publicAddress(private, ipv6)
	assert.False(t, ok)
}

func routeTable(id, vpc string, main bool, subnets []string, routes ...types.Route) types.RouteTable {
	rt := types.RouteTable{RouteTableId: awssdk.String(id), VpcId: awssdk.String(vpc), Routes: routes}
	if main {
		rt.Associations = append(rt.Associations, types.RouteTableAssociation{Main: awssdk.Bool(true)})
	}
	for _, s := range subnets {
		rt.Associations = append(rt.Associations, types.RouteTableAssociation{SubnetId: awssdk.String(s)})
	}
	return rt
}

func igwRoute(dest string) types.Route {
	return types.Route{DestinationCidrBlock: awssdk.String(dest), GatewayId: awssdk.String("igw-1"), State: types.RouteStateActive}
}

func TestRouteTableExplicitAssociationWins(t *testing.T) {
	t.Parallel()

	tables := []types.RouteTable{
		routeTable("rtb-main", "vpc-a", true, nil),
		routeTable("rtb-explicit", "vpc-a", false, []string{"subnet-1"}),
	}
	rt, ok := routeTableFor(tables, "subnet-1", "vpc-a")
	assert.True(t, ok)
	assert.Equal(t, "rtb-explicit", awssdk.ToString(rt.RouteTableId))
}

func TestRouteTableFallsBackToSameVPCMain(t *testing.T) {
	t.Parallel()

	// vpc-a's main table routes to the internet; vpc-b's does not. A subnet in vpc-b
	// without an explicit association must use vpc-b's main table.
	tables := []types.RouteTable{
		routeTable("rtb-a-main", "vpc-a", true, nil, igwRoute("0.0.0.0/0")),
		routeTable("rtb-b-main", "vpc-b", true, nil),
	}
	rt, ok := routeTableFor(tables, "subnet-b", "vpc-b")
	assert.True(t, ok)
	assert.Equal(t, "rtb-b-main", awssdk.ToString(rt.RouteTableId))

	_, ok = routeTableFor(tables, "subnet-c", "vpc-c")
	assert.False(t, ok, "no table for an unknown VPC")
}

func TestInternetRoute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		route  types.Route
		family family
		want   bool
	}{
		{"IPv4 default to igw", igwRoute("0.0.0.0/0"), ipv4, true},
		{"split route half of the internet", igwRoute("0.0.0.0/1"), ipv4, true},
		{"specific public range to igw", igwRoute("198.51.100.0/24"), ipv4, true},
		{"private range to igw carries no internet traffic", igwRoute("10.0.0.0/8"), ipv4, false},
		{"IPv6 default to igw", types.Route{DestinationIpv6CidrBlock: awssdk.String("::/0"), GatewayId: awssdk.String("igw-1")}, ipv6, true},
		{"IPv6 default to egress-only gateway", types.Route{DestinationIpv6CidrBlock: awssdk.String("::/0"), GatewayId: awssdk.String("eigw-1")}, ipv6, false},
		{"default to NAT gateway", types.Route{DestinationCidrBlock: awssdk.String("0.0.0.0/0"), NatGatewayId: awssdk.String("nat-1")}, ipv4, false},
		{"blackhole", types.Route{DestinationCidrBlock: awssdk.String("0.0.0.0/0"), GatewayId: awssdk.String("igw-1"), State: types.RouteStateBlackhole}, ipv4, false},
		{"local route only", types.Route{DestinationCidrBlock: awssdk.String("10.0.0.0/16"), GatewayId: awssdk.String("local")}, ipv4, false},
		{"IPv4 route, IPv6 family", igwRoute("0.0.0.0/0"), ipv6, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, ok := internetRoute(types.RouteTable{Routes: []types.Route{tt.route}}, tt.family)
			assert.Equal(t, tt.want, ok)
		})
	}
}

func entry(rule int32, action types.RuleAction, protocol, cidr string, from, to int32) types.NetworkAclEntry {
	e := types.NetworkAclEntry{
		RuleNumber: awssdk.Int32(rule), RuleAction: action, Protocol: awssdk.String(protocol),
		Egress: awssdk.Bool(false), CidrBlock: awssdk.String(cidr),
	}
	if from >= 0 {
		e.PortRange = &types.PortRange{From: awssdk.Int32(from), To: awssdk.Int32(to)}
	}
	return e
}

func egressOf(e types.NetworkAclEntry) types.NetworkAclEntry {
	e.Egress = awssdk.Bool(true)
	return e
}

func TestNACLDecision(t *testing.T) {
	t.Parallel()

	allowAll := entry(100, types.RuleActionAllow, "-1", "0.0.0.0/0", -1, -1)
	denyDefault := entry(defaultNACLRule, types.RuleActionDeny, "-1", "0.0.0.0/0", -1, -1)
	deny22 := entry(90, types.RuleActionDeny, "6", "0.0.0.0/0", 22, 22)

	tests := []struct {
		name        string
		entries     []types.NetworkAclEntry
		wantAllowed bool
		wantRule    int32
		wantFrom    string
	}{
		{"allow all", []types.NetworkAclEntry{allowAll, denyDefault}, true, 100, "0.0.0.0/0"},
		{"deny 22 before allow all", []types.NetworkAclEntry{deny22, allowAll, denyDefault}, false, 90, ""},
		{"order is by rule number, not position", []types.NetworkAclEntry{allowAll, denyDefault, deny22}, false, 90, ""},
		{"narrow deny does not block the rest of the internet", []types.NetworkAclEntry{
			entry(50, types.RuleActionDeny, "6", "198.51.100.0/24", 22, 22), allowAll}, true, 100, "0.0.0.0/0"},
		{"narrow allow before a deny admits that range", []types.NetworkAclEntry{
			entry(100, types.RuleActionAllow, "6", "203.0.113.0/24", 22, 22), entry(200, types.RuleActionDeny, "-1", "0.0.0.0/0", -1, -1)}, true, 100, "203.0.113.0/24"},
		{"split allows cover the internet", []types.NetworkAclEntry{
			entry(100, types.RuleActionAllow, "-1", "0.0.0.0/1", -1, -1), entry(110, types.RuleActionAllow, "-1", "128.0.0.0/1", -1, -1), denyDefault}, true, 100, "0.0.0.0/1"},
		{"allow for a private range only is not internet", []types.NetworkAclEntry{
			entry(100, types.RuleActionAllow, "-1", "10.0.0.0/8", -1, -1), denyDefault}, false, defaultNACLRule, ""},
		{"deny everything then a narrow allow admits nothing", []types.NetworkAclEntry{
			entry(50, types.RuleActionDeny, "-1", "0.0.0.0/0", -1, -1), entry(100, types.RuleActionAllow, "6", "203.0.113.0/24", 22, 22)}, false, 50, ""},
		{"deny for another port is skipped", []types.NetworkAclEntry{
			entry(90, types.RuleActionDeny, "6", "0.0.0.0/0", 3389, 3389), allowAll}, true, 100, "0.0.0.0/0"},
		{"only the default rule", []types.NetworkAclEntry{denyDefault}, false, defaultNACLRule, ""},
		{"egress rules do not admit inbound traffic", []types.NetworkAclEntry{egressOf(allowAll)}, false, defaultNACLRule, ""},
		{"no entries at all", nil, false, defaultNACLRule, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := naclDecision(types.NetworkAcl{Entries: tt.entries}, 22, ipv4, false)
			assert.Equal(t, tt.wantAllowed, v.Allowed)
			assert.Equal(t, tt.wantRule, v.Rule)
			if tt.wantAllowed {
				assert.Equal(t, tt.wantFrom, v.From.String())
			}
		})
	}
}

func TestNACLDecisionEgress(t *testing.T) {
	t.Parallel()

	only443 := egressOf(entry(100, types.RuleActionAllow, "6", "0.0.0.0/0", 443, 443))
	ephemeral := egressOf(entry(100, types.RuleActionAllow, "6", "0.0.0.0/0", 1024, 65535))

	assert.False(t, naclDecision(types.NetworkAcl{Entries: []types.NetworkAclEntry{only443}}, ephemeralPort, ipv4, true).Allowed,
		"return traffic to ephemeral ports is denied")
	assert.True(t, naclDecision(types.NetworkAcl{Entries: []types.NetworkAclEntry{ephemeral}}, ephemeralPort, ipv4, true).Allowed)
}

func TestNACLDecisionIPv6(t *testing.T) {
	t.Parallel()

	v6Allow := types.NetworkAclEntry{
		RuleNumber: awssdk.Int32(101), RuleAction: types.RuleActionAllow, Protocol: awssdk.String("-1"),
		Egress: awssdk.Bool(false), Ipv6CidrBlock: awssdk.String("::/0"),
	}
	v4Allow := entry(100, types.RuleActionAllow, "-1", "0.0.0.0/0", -1, -1)

	v := naclDecision(types.NetworkAcl{Entries: []types.NetworkAclEntry{v4Allow, v6Allow}}, 22, ipv6, false)
	assert.True(t, v.Allowed)
	assert.Equal(t, int32(101), v.Rule)

	assert.False(t, naclDecision(types.NetworkAcl{Entries: []types.NetworkAclEntry{v4Allow}}, 22, ipv6, false).Allowed,
		"an IPv4 rule does not admit IPv6 traffic")
}

func TestCovered(t *testing.T) {
	t.Parallel()

	pfx := netip.MustParsePrefix
	tests := []struct {
		name string
		p    string
		set  []string
		want bool
	}{
		{"inside one prefix", "10.1.0.0/16", []string{"10.0.0.0/8"}, true},
		{"union of two halves", "0.0.0.0/0", []string{"0.0.0.0/1", "128.0.0.0/1"}, true},
		{"one half missing", "0.0.0.0/0", []string{"0.0.0.0/1"}, false},
		{"no overlap", "203.0.113.0/24", []string{"10.0.0.0/8"}, false},
		{"single address", "203.0.113.7/32", []string{"203.0.113.0/24"}, true},
		{"IPv6", "fd00::/8", []string{"fc00::/7"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var set []netip.Prefix
			for _, s := range tt.set {
				set = append(set, pfx(s))
			}
			assert.Equal(t, tt.want, covered(pfx(tt.p), set))
		})
	}
}

func TestNACLFor(t *testing.T) {
	t.Parallel()

	acls := []types.NetworkAcl{{
		NetworkAclId: awssdk.String("acl-1"),
		Associations: []types.NetworkAclAssociation{{SubnetId: awssdk.String("subnet-1")}},
	}}
	acl, ok := naclFor(acls, "subnet-1")
	assert.True(t, ok)
	assert.Equal(t, "acl-1", awssdk.ToString(acl.NetworkAclId))

	_, ok = naclFor(acls, "subnet-2")
	assert.False(t, ok)
}
