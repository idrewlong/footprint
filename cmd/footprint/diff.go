package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/idrewlong/footprint/pkg/casefile"
)

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"h":    true,
		"help": true,
	}, nil)
	if splitErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", splitErr)
		return 2
	}
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positionals) != 2 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	oldSaved, err := casefile.Load(positionals[0])
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	newSaved, err := casefile.Load(positionals[1])
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	if err := casefile.WriteDiff(stdout, casefile.Diff(oldSaved.Report, newSaved.Report)); err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	return 0
}
