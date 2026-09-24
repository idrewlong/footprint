package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/casefile"
	"github.com/idrewlong/footprint/pkg/graph"
	"github.com/idrewlong/footprint/pkg/report"
)

// runExport builds a pivot graph from one or more saved case files and writes
// it in an analyst format: graphml, neo4j, stix, misp, or maltego. Several
// case files are merged first, so an email case and a domain case export as
// one connected graph. It reads only local files and connects only what the
// reports already found.
func runExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		format string
		out    string
	)
	fs.StringVar(&format, "format", "graphml", "graphml, neo4j, stix, misp, or maltego")
	fs.StringVar(&out, "out", "", "write to this file instead of stdout")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"h":    true,
		"help": true,
	}, map[string]bool{
		"format": true,
		"out":    true,
	})
	if splitErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", splitErr)
		return 2
	}
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positionals) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
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
	g := graph.Build(merged)

	sink := stdout
	if out != "" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 1
		}
		defer f.Close()
		sink = f
	}

	var writeErr error
	switch strings.ToLower(format) {
	case "graphml":
		writeErr = graph.WriteGraphML(sink, g)
	case "neo4j":
		writeErr = graph.WriteNeo4j(sink, g)
	case "stix":
		writeErr = graph.WriteSTIX(sink, g, time.Time{})
	case "misp":
		writeErr = graph.WriteMISP(sink, g, "footprint "+casefile.Subject(merged))
	case "maltego":
		writeErr = graph.WriteMaltegoCSV(sink, g)
	default:
		fmt.Fprintf(stderr, "footprint: unknown format %q (use graphml, neo4j, stix, misp, or maltego)\n", format)
		return 2
	}
	if writeErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", writeErr)
		return 1
	}
	if out != "" {
		fmt.Fprintf(stderr, "wrote %s (%s, %d nodes, %d edges)\n", out, strings.ToLower(format), len(g.Nodes), len(g.Edges))
	}
	return 0
}
