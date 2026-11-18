package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	demoProwler   = "../../examples/demo-account/prowler.ocsf.json"
	demoInventory = "../../examples/demo-account/aws"
	gapProwler    = "../../examples/missing-permission/prowler.ocsf.json"
	gapInventory  = "../../examples/missing-permission/aws"
)

func runCLI(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunDemoAccount(t *testing.T) {
	t.Parallel()

	code, out, _ := runCLI("--prowler", demoProwler, "--inventory", demoInventory)

	assert.Equal(t, exitFindings, code)
	assert.Contains(t, out, "Prowler findings verified: 6 · EXPOSED 2 · NOT_EXPOSED 3 · UNKNOWN 0 · UNVERIFIED 1")
	assert.Contains(t, out, "instance/i-0web")
	assert.Contains(t, out, "network ACL acl-0locked: inbound rule 90 denies tcp/22 from the internet", "the look-alike of i-0web is not exposed")
	assert.Contains(t, out, "route table rtb-0bmain: no active route to an internet gateway", "uses vpc-0b's own main route table")
	assert.Contains(t, out, "at 2001:db8:a::10 (IPv6, from ::/0)", "IPv6-only exposure that Prowler rated medium")
}

func TestRunMissingPermission(t *testing.T) {
	t.Parallel()

	code, out, _ := runCLI("--prowler", gapProwler, "--inventory", gapInventory, "--format", "json")
	assert.Equal(t, exitFindings, code)

	var got struct {
		Results []struct {
			Status  string   `json:"status"`
			Missing []string `json:"missing"`
		} `json:"results"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Len(t, got.Results, 1)
	assert.Equal(t, "UNKNOWN", got.Results[0].Status)
	assert.Equal(t, []string{"ec2:DescribeNetworkAcls (AccessDenied)"}, got.Results[0].Missing)
}

func TestRunInterrupted(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	code := run(ctx, []string{"--prowler", demoProwler, "--inventory", demoInventory}, &stdout, &stderr)

	assert.Equal(t, exitError, code, "an interrupted run never looks clean")
	assert.Contains(t, stderr.String(), "the report above is incomplete")
}

func TestRunExitCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"exposed fails by default", []string{"--prowler", demoProwler, "--inventory", demoInventory}, exitFindings},
		{"unknown fails by default", []string{"--prowler", gapProwler, "--inventory", gapInventory}, exitFindings},
		{"unknown passes with --fail-on exposed", []string{"--prowler", gapProwler, "--inventory", gapInventory, "--fail-on", "exposed"}, exitOK},
		{"never", []string{"--prowler", demoProwler, "--inventory", demoInventory, "--fail-on", "never"}, exitOK},
		{"help", []string{"-h"}, exitOK},
		{"missing flags", []string{"--prowler", demoProwler}, exitUsage},
		{"bad format", []string{"--prowler", demoProwler, "--inventory", demoInventory, "--format", "xml"}, exitUsage},
		{"bad fail-on", []string{"--prowler", demoProwler, "--inventory", demoInventory, "--fail-on", "maybe"}, exitUsage},
		{"unknown flag", []string{"--nope"}, exitUsage},
		{"stray argument, e.g. a glob that matched two files", []string{"--prowler", demoProwler, "--inventory", demoInventory, "extra.json"}, exitUsage},
		{"prowler file not found", []string{"--prowler", "nope.json", "--inventory", demoInventory}, exitError},
		{"inventory not a directory", []string{"--prowler", demoProwler, "--inventory", demoProwler}, exitError},
		{"inventory is not Prowler JSON", []string{"--prowler", demoInventory + "/describe-instances.json", "--inventory", demoInventory}, exitError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			code, _, _ := runCLI(tt.args...)
			assert.Equal(t, tt.want, code)
		})
	}
}
