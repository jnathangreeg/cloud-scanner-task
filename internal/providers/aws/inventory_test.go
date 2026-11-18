package aws

import (
	"testing"
	"testing/fstest"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Shapes copied from `aws ec2 describe-* --output json`.
const (
	instancesJSON = `{"Reservations":[{"Instances":[
	  {"InstanceId":"i-0web","State":{"Name":"running"},"SubnetId":"subnet-0pub","VpcId":"vpc-0a",
	   "PublicIpAddress":"203.0.113.10","SecurityGroups":[{"GroupId":"sg-0ssh"}]},
	  {"InstanceId":"i-0private","State":{"Name":"running"},"SubnetId":"subnet-0priv","VpcId":"vpc-0a",
	   "SecurityGroups":[{"GroupId":"sg-0ssh"}]}]}]}`
	groupsJSON = `{"SecurityGroups":[{"GroupId":"sg-0ssh","IpPermissions":[
	  {"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]}]}`
	routesJSON = `{"RouteTables":[
	  {"RouteTableId":"rtb-0pub","VpcId":"vpc-0a","Associations":[{"SubnetId":"subnet-0pub"}],
	   "Routes":[{"DestinationCidrBlock":"0.0.0.0/0","GatewayId":"igw-0a","State":"active"}]},
	  {"RouteTableId":"rtb-0main","VpcId":"vpc-0a","Associations":[{"Main":true}],"Routes":[]}]}`
	aclsJSON = `{"NetworkAcls":[{"NetworkAclId":"acl-0open","VpcId":"vpc-0a",
	  "Associations":[{"SubnetId":"subnet-0pub"}],
	  "Entries":[{"RuleNumber":100,"Protocol":"-1","RuleAction":"allow","Egress":false,"CidrBlock":"0.0.0.0/0"}]}]}`
)

func fullFS() fstest.MapFS {
	return fstest.MapFS{
		"describe-instances.json":       {Data: []byte(instancesJSON)},
		"describe-security-groups.json": {Data: []byte(groupsJSON)},
		"describe-route-tables.json":    {Data: []byte(routesJSON)},
		"describe-network-acls.json":    {Data: []byte(aclsJSON)},
	}
}

func TestLoadInventory(t *testing.T) {
	t.Parallel()

	inv, err := LoadInventory(fullFS())
	require.NoError(t, err)

	assert.Len(t, inv.Instances, 2)
	assert.Equal(t, "203.0.113.10", awssdk.ToString(inv.Instances["i-0web"].PublicIpAddress))
	assert.Contains(t, inv.SecurityGroups, "sg-0ssh")
	assert.Len(t, inv.RouteTables, 2)
	assert.Len(t, inv.NetworkACLs, 1)
	assert.Empty(t, inv.Missing)
}

func TestLoadInventoryRecordsMissingFile(t *testing.T) {
	t.Parallel()

	fsys := fullFS()
	delete(fsys, "describe-network-acls.json")

	inv, err := LoadInventory(fsys)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		ActionDescribeNetworkAcls: "not collected (describe-network-acls.json not found)",
	}, inv.Missing)
}

func TestLoadInventoryRecordsAccessDenied(t *testing.T) {
	t.Parallel()

	fsys := fullFS()
	fsys["errors.json"] = &fstest.MapFile{Data: []byte(`{"ec2:DescribeNetworkAcls":"AccessDenied"}`)}

	inv, err := LoadInventory(fsys)
	require.NoError(t, err)
	assert.Equal(t, "AccessDenied", inv.Missing[ActionDescribeNetworkAcls])
	assert.Empty(t, inv.NetworkACLs, "data for a failed action is not loaded")
}

func TestLoadInventoryBadJSON(t *testing.T) {
	t.Parallel()

	fsys := fullFS()
	fsys["describe-route-tables.json"] = &fstest.MapFile{Data: []byte(`{`)}

	_, err := LoadInventory(fsys)
	assert.ErrorContains(t, err, "decoding describe-route-tables.json")
}

func TestLoadInventoryNullErrorsFile(t *testing.T) {
	t.Parallel()

	fsys := fullFS()
	fsys["errors.json"] = &fstest.MapFile{Data: []byte(`null`)}
	delete(fsys, "describe-network-acls.json")

	inv, err := LoadInventory(fsys)
	require.NoError(t, err)
	assert.Contains(t, inv.Missing, ActionDescribeNetworkAcls)
}
