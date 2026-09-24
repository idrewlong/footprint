package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/idrewlong/footprint/pkg/casefile"
)

// runVerify checks the tamper-evident audit ledger of a case directory. It
// confirms every saved case file is unchanged, that the ledger's chain is
// intact, and that each entry's signature is valid. It exits non-zero when
// anything fails, so it can gate a workflow.
func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var caseDir string
	fs.StringVar(&caseDir, "case-dir", "", "case directory to verify")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"h":    true,
		"help": true,
	}, map[string]bool{
		"case-dir": true,
	})
	if splitErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", splitErr)
		return 2
	}
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	// The directory may be given positionally or with --case-dir.
	if len(positionals) == 1 && caseDir == "" {
		caseDir = positionals[0]
	} else if len(positionals) > 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	dir := caseDir
	if dir == "" {
		var err error
		dir, err = casefile.DefaultDir()
		if err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 1
		}
	}
	report, err := casefile.Verify(dir)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	if report.Entries == 0 {
		fmt.Fprintf(stdout, "No audit ledger in %s.\n", dir)
		return 0
	}
	if report.OK() {
		fmt.Fprintf(stdout, "OK: %s verified, chain and signatures intact.\n", counted(report.Entries, "case", "cases"))
		return 0
	}
	fmt.Fprintf(stdout, "FAILED: %d problem(s) in %s\n", len(report.Problems), dir)
	for _, p := range report.Problems {
		fmt.Fprintf(stdout, "- %s\n", p)
	}
	return 1
}
