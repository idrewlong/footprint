package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/report"
)

func runUser(args []string, stdout, stderr io.Writer, catalog catalogFunc) int {
	fs := flag.NewFlagSet("user", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		onlyFound   bool
		asJSON      bool
		asMarkdown  bool
		proxyURL    string
		concurrency int
		timeout     time.Duration
		categories  stringList
		names       stringList
	)
	fs.BoolVar(&onlyFound, "only-found", false, "omit non-hits from a JSON report")
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.StringVar(&proxyURL, "proxy", "", "route checks through a proxy (http, https, socks5, socks5h)")
	fs.IntVar(&concurrency, "concurrency", checker.DefaultConcurrency, "parallel checks")
	fs.DurationVar(&timeout, "timeout", checker.DefaultTimeout, "per-site timeout")
	fs.Var(&categories, "category", "category to check")
	fs.Var(&names, "site", "profile to check")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"only-found": true,
		"json":       true,
		"md":         true,
		"h":          true,
		"help":       true,
	}, map[string]bool{
		"concurrency": true,
		"timeout":     true,
		"category":    true,
		"site":        true,
		"proxy":       true,
	})
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
	transport, proxyErr := proxyTransport(proxyURL)
	if proxyErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", proxyErr)
		return 2
	}
	defer transport.CloseIdleConnections()
	if concurrency < 1 {
		fmt.Fprintln(stderr, "footprint: --concurrency must be at least 1")
		return 2
	}
	if timeout <= 0 {
		fmt.Fprintln(stderr, "footprint: --timeout must be greater than 0")
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	username, ok := normalizeUsername(positionals[0])
	if !ok {
		fmt.Fprintln(stderr, "footprint: username is not valid")
		return 2
	}
	selected, err := catalog(categories, names)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	human := !asJSON && !asMarkdown
	label := fmt.Sprintf("checking %s across %d profiles", username, len(selected))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	prog := newProgress(stderr, human && isTerminal(stderr), label, username, len(selected))
	prog.start()
	start := time.Now()
	var results []checker.Result
	for res := range checker.Run(ctx, username, selected, checker.Options{Concurrency: concurrency, Timeout: timeout, Transport: transport}) {
		results = append(results, res)
		prog.add(res.Status)
	}
	prog.finish()
	doc := report.BuildUser(username, results, onlyFound && asJSON)
	report.ScoreConfidence(&doc)
	elapsed := time.Since(start)
	if human {
		if err := report.WriteHuman(stdout, doc, elapsed, useColor(stdout)); err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 1
		}
		return 0
	}
	var writeErr error
	if asJSON {
		writeErr = report.WriteJSON(stdout, doc)
	} else {
		writeErr = report.WriteMarkdown(stdout, doc, report.Meta{Version: toolVersion(), RanAt: start, Elapsed: elapsed})
	}
	if writeErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", writeErr)
		return 1
	}
	return 0
}

func normalizeUsername(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "@") {
		return "", false
	}
	if len(raw) > 39 || strings.ContainsAny(raw, " \t/\\?#%") {
		return "", false
	}
	for i, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '.' || r == '_' || r == '-'):
		default:
			return "", false
		}
	}
	return raw, true
}
