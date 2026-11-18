// Command scanner verifies Prowler's "port exposed to the internet" findings
// against the real AWS network path.
//
//	scanner --prowler findings.ocsf.json --inventory ./aws-snapshot [--format text|json] [--fail-on unknown|exposed|never]
//
// Exit codes: 0 nothing at the --fail-on threshold, 1 findings at the threshold,
// 2 usage error, 3 input error or interrupted run.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/jnathangreeg/cloud-scanner-task/internal/finding"
	"github.com/jnathangreeg/cloud-scanner-task/internal/providers/aws"
	"github.com/jnathangreeg/cloud-scanner-task/internal/prowler"
	"github.com/jnathangreeg/cloud-scanner-task/internal/report"
	"github.com/jnathangreeg/cloud-scanner-task/internal/verify"
)

const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
	exitError    = 3 // input error or interrupted run
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type options struct {
	prowlerFile  string
	inventoryDir string
	format       string
	failOn       string
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}

	candidates, inv, err := load(opts)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return exitError
	}

	results, runErr := verify.NewRegistry(aws.NewExposureVerifier(inv)).Run(ctx, candidates)

	write := report.Text
	if opts.format == "json" {
		write = report.JSON
	}
	if err := write(stdout, results); err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	if runErr != nil {
		_, _ = fmt.Fprintln(stderr, "error:", runErr, "(the report above is incomplete)")
		return exitError
	}
	return exitCode(results, opts.failOn)
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("scanner", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.prowlerFile, "prowler", "", "Prowler JSON-OCSF findings file (required)")
	fs.StringVar(&o.inventoryDir, "inventory", "", "directory with aws ec2 describe-*.json files (required)")
	fs.StringVar(&o.format, "format", "text", "output format: text or json")
	fs.StringVar(&o.failOn, "fail-on", "unknown", "exit 1 on: unknown (EXPOSED or UNKNOWN), exposed (EXPOSED only) or never")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	switch {
	case fs.NArg() > 0:
		return o, fmt.Errorf("unexpected arguments %q (--prowler takes exactly one file)", fs.Args())
	case o.prowlerFile == "" || o.inventoryDir == "":
		return o, errors.New("--prowler and --inventory are required")
	case o.format != "text" && o.format != "json":
		return o, fmt.Errorf("--format must be text or json, got %q", o.format)
	case o.failOn != "exposed" && o.failOn != "unknown" && o.failOn != "never":
		return o, fmt.Errorf("--fail-on must be exposed, unknown or never, got %q", o.failOn)
	}
	return o, nil
}

func load(o options) ([]finding.Candidate, *aws.Inventory, error) {
	f, err := os.Open(o.prowlerFile) //nolint:gosec // G304: the path is the operator's own CLI argument
	if err != nil {
		return nil, nil, fmt.Errorf("opening Prowler findings: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only file: a close error cannot lose data

	candidates, err := prowler.ReadOCSF(f)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", o.prowlerFile, err)
	}
	if info, err := os.Stat(o.inventoryDir); err != nil || !info.IsDir() {
		return nil, nil, fmt.Errorf("inventory %s is not a readable directory", o.inventoryDir)
	}
	inv, err := aws.LoadInventory(os.DirFS(o.inventoryDir))
	if err != nil {
		return nil, nil, fmt.Errorf("loading inventory %s: %w", o.inventoryDir, err)
	}
	return candidates, inv, nil
}

func exitCode(results []finding.Result, failOn string) int {
	counts := report.Counts(results)
	switch {
	case failOn == "never":
		return exitOK
	case counts[finding.StatusExposed] > 0:
		return exitFindings
	case failOn == "unknown" && counts[finding.StatusUnknown] > 0:
		return exitFindings
	default:
		return exitOK
	}
}
