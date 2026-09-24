package main

import (
	"fmt"
	"io"
	"runtime/debug"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/casefile"
	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/profiles"
	"github.com/idrewlong/footprint/pkg/report"
	"github.com/idrewlong/footprint/pkg/sites"
)

const (
	secUserAgent = "footprint/dev (local research)"
	usage        = `footprint finds accounts registered to an email address, or public profiles for a username.

An email scan checks that address, including breach names. It does not look up the mailbox name.
A username scan checks public profiles. Pass both when you want the two together.
Passwords and other stolen values are not requested or shown.

The terminal lists found accounts, one action link each, and names sites it could not check.
Each breach name is on its own line. Color is used when stdout is a terminal.
The summary still counts every check.
JSON includes found, not found, rate limited, and error.
Markdown is a one-page case note: a bottom line, findings with the signal each check used, coverage, and actions.
A username hit includes the public profile link and display name when the site shows one.
A found row includes the method and the evidence sentence.

Usage:
  footprint scan email <email> [flags]
  footprint scan username <username> [flags]
  footprint scan email <email> username <username> [flags]
  footprint user <username> [flags]
  footprint sites [flags]
  footprint lookup domain <domain-or-email> [--certs] [--timeout 10s] [--json|--md] [--save] [--case-dir path]
  footprint lookup ip <ip> [--geoip path] [--no-update] [--timeout 10s] [--json|--md] [--save] [--case-dir path]
  footprint lookup entity <name> --sdn path [--timeout 10s] [--json|--md] [--save] [--case-dir path]
  footprint diff <old.json> <new.json>
  footprint note <report.json>... [--json|--md]

Scan and user flags:
  --only-found        omit non-hits from a JSON report
  --json              write a JSON report to stdout
  --md                write a Markdown report to stdout
  --concurrency n     parallel checks (default 16)
  --timeout 10s       per-site timeout
  --category name     check these categories (repeatable, or comma-separated)
  --site name         check these sites (repeatable, or comma-separated)
  --save              write the report under the case directory
  --case-dir path     case directory (default ~/.local/share/footprint)

Sites flags:
  --category name     list one category
  --json              write the site list as JSON

Examples:
  footprint scan email me@example.com
  footprint scan username octocat
  footprint scan email me@example.com username octocat
  footprint scan email me@example.com --json
  footprint user octocat
  footprint sites
  footprint sites --category dev
  footprint lookup domain ada@example.com
  footprint lookup ip 8.8.8.8
  footprint lookup entity "Apple Inc." --sdn sdn.csv
  footprint diff old.json new.json
  footprint note a.json b.json --md
`
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

type catalogFunc func(categories, names []string) ([]checker.Site, error)

func execute(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "scan" {
		return runCommand(args, stdout, stderr, matchCatalog(sites.All), matchCatalog(profiles.All))
	}
	return executeCatalog(args, stdout, stderr, sites.Select)
}

func executeCatalog(args []string, stdout, stderr io.Writer, catalog catalogFunc) int {
	return runCommand(args, stdout, stderr, catalog, nil)
}

func runCommand(args []string, stdout, stderr io.Writer, catalog, profilesCatalog catalogFunc) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr, catalog, profilesCatalog)
	case "user":
		return runUser(args[1:], stdout, stderr, profiles.Select)
	case "sites":
		return runSites(args[1:], stdout, stderr, catalog)
	case "lookup":
		return runLookup(args[1:], stdout, stderr, liveLookupDeps())
	case "diff":
		return runDiff(args[1:], stdout, stderr)
	case "note":
		return runNote(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func toolVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	return info.Main.Version
}

func counted(n int, one, many string) string {
	word := many
	if n == 1 {
		word = one
	}
	return fmt.Sprintf("%d %s", n, word)
}

func writeReport(stdout, stderr io.Writer, doc report.Document, asJSON, asMarkdown bool, start time.Time, elapsed time.Duration) error {
	if !asJSON && !asMarkdown {
		if err := report.WriteHuman(stdout, doc, elapsed, useColor(stdout)); err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return err
		}
		return nil
	}
	var writeErr error
	if asJSON {
		writeErr = report.WriteJSON(stdout, doc)
	} else {
		writeErr = report.WriteMarkdown(stdout, doc, report.Meta{Version: toolVersion(), RanAt: start, Elapsed: elapsed})
	}
	if writeErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", writeErr)
	}
	return writeErr
}

func maybeSave(stderr io.Writer, save bool, caseDir, kind string, doc report.Document, start time.Time, elapsed time.Duration) int {
	if !save {
		return 0
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
	path, err := casefile.Save(dir, casefile.Saved{
		Version:   toolVersion(),
		RanAt:     start,
		ElapsedMS: elapsed.Milliseconds(),
		Kind:      kind,
		Report:    doc,
	})
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "saved %s\n", path)
	return 0
}

// splitArgs lets flags follow the email, which is how the documented
// commands are written. The standard flag parser stops at the first
// non-flag otherwise. A value flag with no value is a usage error.
func splitArgs(args []string, boolFlags, valueFlags map[string]bool) (flags, positionals []string, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		name := strings.TrimLeft(arg, "-")
		if name == arg || name == "" {
			positionals = append(positionals, arg)
			continue
		}
		key, _, hasValue := strings.Cut(name, "=")
		switch {
		case boolFlags[key]:
			flags = append(flags, arg)
		case valueFlags[key]:
			flags = append(flags, arg)
			if !hasValue {
				if i+1 >= len(args) {
					return nil, nil, fmt.Errorf("flag needs an argument: --%s", key)
				}
				i++
				flags = append(flags, args[i])
			}
		default:
			positionals = append(positionals, arg)
		}
	}
	return flags, positionals, nil
}
