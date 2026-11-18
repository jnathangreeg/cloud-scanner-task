package aws

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// family is an IP address family. Every hop is evaluated once per family,
// because IPv4 and IPv6 have separate rules, addresses and routes.
type family int

const (
	ipv4 family = iota
	ipv6
)

func (f family) String() string {
	if f == ipv6 {
		return "IPv6"
	}
	return "IPv4"
}

// anywhere is the CIDR meaning "every address" for the family.
func (f family) anywhere() string {
	if f == ipv6 {
		return "::/0"
	}
	return "0.0.0.0/0"
}

const (
	// defaultNACLRule is the number AWS gives the implicit IPv4 "*" rule of every network ACL
	// (the IPv6 one is 32768).
	defaultNACLRule int32 = 32767
	// ephemeralPort stands for the client's source port of return traffic. Network ACLs are
	// stateless, so outbound rules must allow it. 49152 is inside every common OS range.
	ephemeralPort int32 = 49152
)

// nonInternet lists ranges that are never internet sources: private, shared, loopback,
// link-local and "this network". A rule that only covers these does not expose anything.
var nonInternet = map[family][]netip.Prefix{
	ipv4: {
		netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	},
	ipv6: {
		netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	},
}

// openRule is a security group rule that lets the port in from anywhere.
type openRule struct {
	GroupID string
	Perm    types.IpPermission
}

// sgOpenRules returns every security group rule that allows TCP port from anywhere (0.0.0.0/0 or ::/0),
// which is the condition Prowler's checks report. Security groups only add allows, so any one is enough.
func sgOpenRules(groups []types.SecurityGroup, port int32, f family) []openRule {
	var open []openRule
	for _, g := range groups {
		for _, p := range g.IpPermissions {
			if tcpCovers(awssdk.ToString(p.IpProtocol), p.FromPort, p.ToPort, port) && permFromAnywhere(p, f) {
				open = append(open, openRule{GroupID: awssdk.ToString(g.GroupId), Perm: p})
			}
		}
	}
	return open
}

// tcpCovers reports whether a rule with this protocol and port range applies to TCP port.
// Protocol "-1" means all traffic. EC2 reports TCP as "tcp" in security groups and "6" in network ACLs.
func tcpCovers(protocol string, from, to *int32, port int32) bool {
	switch protocol {
	case "-1":
		return true
	case "tcp", "6":
		if from == nil || to == nil {
			return true
		}
		return *from <= port && port <= *to
	default:
		return false
	}
}

func permFromAnywhere(p types.IpPermission, f family) bool {
	if f == ipv6 {
		return slices.ContainsFunc(p.Ipv6Ranges, func(r types.Ipv6Range) bool { return awssdk.ToString(r.CidrIpv6) == f.anywhere() })
	}
	return slices.ContainsFunc(p.IpRanges, func(r types.IpRange) bool { return awssdk.ToString(r.CidrIp) == f.anywhere() })
}

// publicAddress returns the instance's internet-routable address for the family.
// Every IPv6 address in a VPC is globally unique, so any IPv6 address counts.
func publicAddress(in types.Instance, f family) (string, bool) {
	if f == ipv4 {
		ip := awssdk.ToString(in.PublicIpAddress)
		return ip, ip != ""
	}
	if ip := awssdk.ToString(in.Ipv6Address); ip != "" {
		return ip, true
	}
	for _, eni := range in.NetworkInterfaces {
		for _, a := range eni.Ipv6Addresses {
			if ip := awssdk.ToString(a.Ipv6Address); ip != "" {
				return ip, true
			}
		}
	}
	return "", false
}

// routeTableFor returns the subnet's route table: its explicit association,
// otherwise the main route table of the subnet's own VPC.
func routeTableFor(tables []types.RouteTable, subnetID, vpcID string) (types.RouteTable, bool) {
	for _, rt := range tables {
		for _, a := range rt.Associations {
			if awssdk.ToString(a.SubnetId) == subnetID {
				return rt, true
			}
		}
	}
	for _, rt := range tables {
		if awssdk.ToString(rt.VpcId) != vpcID {
			continue
		}
		for _, a := range rt.Associations {
			if awssdk.ToBool(a.Main) {
				return rt, true
			}
		}
	}
	return types.RouteTable{}, false
}

// internetRoute returns an active route to an internet gateway whose destination contains internet
// addresses: the default route, or split routes such as 0.0.0.0/1. Egress-only gateways (eigw-),
// NAT gateways and blackhole routes do not carry inbound internet traffic.
func internetRoute(rt types.RouteTable, f family) (types.Route, bool) {
	for _, r := range rt.Routes {
		dest := awssdk.ToString(r.DestinationCidrBlock)
		if f == ipv6 {
			dest = awssdk.ToString(r.DestinationIpv6CidrBlock)
		}
		p, err := netip.ParsePrefix(dest)
		if err != nil || !strings.HasPrefix(awssdk.ToString(r.GatewayId), "igw-") || r.State == types.RouteStateBlackhole {
			continue
		}
		if !covered(p.Masked(), nonInternet[f]) {
			return r, true
		}
	}
	return types.Route{}, false
}

// naclFor returns the network ACL associated with the subnet. AWS associates exactly one per subnet.
func naclFor(acls []types.NetworkAcl, subnetID string) (types.NetworkAcl, bool) {
	for _, acl := range acls {
		for _, a := range acl.Associations {
			if awssdk.ToString(a.SubnetId) == subnetID {
				return acl, true
			}
		}
	}
	return types.NetworkAcl{}, false
}

// naclVerdict is the outcome of a network ACL for internet traffic on one port and direction.
type naclVerdict struct {
	Allowed bool
	Rule    int32        // the allowing rule, or the first deny that matched (else the default rule)
	From    netip.Prefix // when allowed: the CIDR of the allowing rule
}

// naclDecision evaluates the ACL's rules in ascending rule number, as AWS does, and reports whether
// any internet address can pass on TCP port. A rule only decides for addresses that no lower-numbered
// matching rule has decided yet, so "deny 0.0.0.0/0 then allow 203.0.113.0/24" admits nothing, while
// "allow 203.0.113.0/24 then deny 0.0.0.0/0" admits that range.
func naclDecision(acl types.NetworkAcl, port int32, f family, egress bool) naclVerdict {
	entries := slices.Clone(acl.Entries)
	slices.SortFunc(entries, func(a, b types.NetworkAclEntry) int {
		return cmp.Compare(awssdk.ToInt32(a.RuleNumber), awssdk.ToInt32(b.RuleNumber))
	})

	decided := slices.Clone(nonInternet[f])
	verdict := naclVerdict{Rule: defaultNACLRule}
	firstDeny := true
	for _, e := range entries {
		p, ok := entryPrefix(e, port, f, egress)
		if !ok || covered(p, decided) {
			continue
		}
		if e.RuleAction == types.RuleActionAllow {
			return naclVerdict{Allowed: true, Rule: awssdk.ToInt32(e.RuleNumber), From: p}
		}
		if firstDeny {
			verdict.Rule, firstDeny = awssdk.ToInt32(e.RuleNumber), false
		}
		decided = append(decided, p)
	}
	return verdict
}

// entryPrefix returns the entry's CIDR if the entry applies to this direction, family and TCP port.
func entryPrefix(e types.NetworkAclEntry, port int32, f family, egress bool) (netip.Prefix, bool) {
	if awssdk.ToBool(e.Egress) != egress {
		return netip.Prefix{}, false
	}
	var from, to *int32
	if e.PortRange != nil {
		from, to = e.PortRange.From, e.PortRange.To
	}
	if !tcpCovers(awssdk.ToString(e.Protocol), from, to, port) {
		return netip.Prefix{}, false
	}
	cidr := awssdk.ToString(e.CidrBlock)
	if f == ipv6 {
		cidr = awssdk.ToString(e.Ipv6CidrBlock)
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// covered reports whether every address in p is inside the union of set.
func covered(p netip.Prefix, set []netip.Prefix) bool {
	overlaps := false
	for _, q := range set {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
		if q.Overlaps(p) {
			overlaps = true
		}
	}
	if !overlaps || p.Bits() == p.Addr().BitLen() {
		return false
	}
	lo, hi := halves(p)
	return covered(lo, set) && covered(hi, set)
}

// halves splits a prefix into its two sub-prefixes one bit longer.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	b := p.Addr().AsSlice()
	lo := netip.PrefixFrom(p.Addr(), bits)
	b[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	hiAddr, _ := netip.AddrFromSlice(b) // b has the same length as p's address, so this cannot fail
	return lo, netip.PrefixFrom(hiAddr, bits)
}
