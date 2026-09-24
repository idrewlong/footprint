package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/idrewlong/footprint/pkg/casefile"
	"github.com/idrewlong/footprint/pkg/report"
)

func runNote(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("note", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		asJSON     bool
		asMarkdown bool
	)
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"json": true,
		"md":   true,
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
	if asJSON && asMarkdown {
		fmt.Fprintln(stderr, "footprint: pass only one of --json or --md")
		return 2
	}
	if len(positionals) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if !asJSON && !asMarkdown {
		asMarkdown = true
	}
	docs := make([]report.Document, 0, len(positionals))
	for _, path := range positionals {
		saved, err := casefile.Load(path)
		if err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 1
		}
		docs = append(docs, saved.Report)
	}
	merged, err := casefile.Merge(docs...)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	report.ScoreConfidence(&merged)
	start := time.Now()
	if err := writeReport(stdout, stderr, merged, asJSON, asMarkdown, start, 0); err != nil {
		return 1
	}
	return 0
}
