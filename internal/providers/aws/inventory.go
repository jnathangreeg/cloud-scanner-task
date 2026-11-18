// Package aws verifies Prowler's EC2 "port exposed to the internet" findings
// against the real network path: security group, public address, route and
// network ACL.
//
// Input is the raw JSON of the read-only EC2 Describe APIs, exactly as
// `aws ec2 describe-* --output json` prints it. It is decoded straight into
// the AWS SDK for Go types, so a live collector would produce the same data.
package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// The read-only API actions this package needs. All are in the SecurityAudit policy.
const (
	ActionDescribeInstances      = "ec2:DescribeInstances"
	ActionDescribeSecurityGroups = "ec2:DescribeSecurityGroups"
	ActionDescribeRouteTables    = "ec2:DescribeRouteTables"
	ActionDescribeNetworkAcls    = "ec2:DescribeNetworkAcls"
)

// errorsFile records collection failures, e.g. {"ec2:DescribeNetworkAcls": "AccessDenied"}.
const errorsFile = "errors.json"

// Inventory is a point-in-time snapshot of the EC2 network data of one account and region.
type Inventory struct {
	Instances      map[string]types.Instance      // by instance ID
	SecurityGroups map[string]types.SecurityGroup // by group ID
	RouteTables    []types.RouteTable
	NetworkACLs    []types.NetworkAcl
	// Missing maps an API action to why its data is absent ("AccessDenied", "not collected").
	Missing map[string]string
}

// LoadInventory reads the describe-*.json files from fsys. A missing file is
// recorded in Inventory.Missing rather than failing, so the verifier can
// report UNKNOWN for exactly the checks that needed it.
func LoadInventory(fsys fs.FS) (*Inventory, error) {
	inv := &Inventory{
		Instances:      map[string]types.Instance{},
		SecurityGroups: map[string]types.SecurityGroup{},
		Missing:        map[string]string{},
	}
	if _, err := readJSON(fsys, errorsFile, &inv.Missing); err != nil {
		return nil, err
	}
	if inv.Missing == nil { // errors.json may contain null
		inv.Missing = map[string]string{}
	}

	var instances ec2.DescribeInstancesOutput
	var groups ec2.DescribeSecurityGroupsOutput
	var routes ec2.DescribeRouteTablesOutput
	var acls ec2.DescribeNetworkAclsOutput
	sources := []struct {
		action, file string
		into         any
	}{
		{ActionDescribeInstances, "describe-instances.json", &instances},
		{ActionDescribeSecurityGroups, "describe-security-groups.json", &groups},
		{ActionDescribeRouteTables, "describe-route-tables.json", &routes},
		{ActionDescribeNetworkAcls, "describe-network-acls.json", &acls},
	}
	for _, s := range sources {
		if _, failed := inv.Missing[s.action]; failed {
			continue
		}
		found, err := readJSON(fsys, s.file, s.into)
		if err != nil {
			return nil, err
		}
		if !found {
			inv.Missing[s.action] = "not collected: " + s.file + " not found"
		}
	}

	for _, r := range instances.Reservations {
		for _, in := range r.Instances {
			inv.Instances[awssdk.ToString(in.InstanceId)] = in
		}
	}
	for _, g := range groups.SecurityGroups {
		inv.SecurityGroups[awssdk.ToString(g.GroupId)] = g
	}
	inv.RouteTables = routes.RouteTables
	inv.NetworkACLs = acls.NetworkAcls
	return inv, nil
}

// readJSON decodes name into v. It reports false, without error, when the file does not exist.
func readJSON(fsys fs.FS, name string, v any) (bool, error) {
	data, err := fs.ReadFile(fsys, name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("decoding %s: %w", name, err)
	}
	return true, nil
}
