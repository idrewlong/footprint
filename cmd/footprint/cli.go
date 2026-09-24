package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/idrewlong/footprint/internal/httpx"
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
  footprint verify [case-dir] [--case-dir path]
  footprint export <case.json>... --format graphml|neo4j|stix|misp|maltego [--out file]

Scans are passive by default: no check emails or otherwise alerts the address.
Password-reset checks, which can email the target, run only with --allow-notify.

Scan and user flags:
  --allow-notify      include checks that email the target (password reset)
  --proxy url         route checks through http, https, socks5, or socks5h
  --batch file        scan many subjects: footprint scan email --batch list.txt
  --only-found        omit non-hits from a JSON report
  --json              write a JSON report to stdout
  --md                write a Markdown report to stdout
  --concurrency n     parallel checks (default 16)
  --timeout 10s       per-site timeout
  --category name     check these categories (repeatable, or comma-separated)
  --site name         check these sites (repeatable, or comma-separated)
  --save              write the report under the case directory
  --case-dir path     case directory (default ~/.local/share/footprint)
  --case-id id        case identifier recorded with a saved report (required with --save)
  --authority text    legal authority recorded with a saved report (required with --save)

A saved report is logged to a signed, append-only audit ledger in the case
directory. 'footprint verify' re-checks that ledger and the saved files.

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
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "export":
		return runExport(args[1:], stdout, stderr)
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

// splitNotify partitions sites into passive checks and alerting checks
// (those whose method can email the target). The scan runs passive checks
// always and alerting ones only when the operator opts in.
func splitNotify(all []checker.Site) (passive, alerting []checker.Site) {
	for _, site := range all {
		if checker.Notifies(site.Method()) {
			alerting = append(alerting, site)
		} else {
			passive = append(passive, site)
		}
	}
	return passive, alerting
}

// proxyTransport builds a shared transport for a scan. An empty proxy uses a
// direct transport. A bad proxy is a usage error so traffic never silently
// falls back to the operator's own IP. The caller closes idle connections.
func proxyTransport(proxyURL string) (*http.Transport, error) {
	return httpx.NewTransportProxy(proxyURL)
}

// notifyNames lists site names for a stderr note.
func notifyNames(sites []checker.Site) string {
	names := make([]string, 0, len(sites))
	for _, site := range sites {
		names = append(names, site.Name())
	}
	return strings.Join(names, ", ")
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

// saveRequest carries everything a --save needs, including the purpose
// fields that tie the saved case to a documented authority.
type saveRequest struct {
	save      bool
	caseDir   string
	kind      string
	caseID    string
	authority string
}

func maybeSave(stderr io.Writer, req saveRequest, doc report.Document, start time.Time, elapsed time.Duration) int {
	if !req.save {
		return 0
	}
	// A saved case is an investigative record, so it must carry the case it
	// belongs to and the authority for the lookup. Unsaved runs are not
	// gated; only the durable record requires them.
	if strings.TrimSpace(req.caseID) == "" || strings.TrimSpace(req.authority) == "" {
		fmt.Fprintln(stderr, "footprint: --save requires --case-id and --authority")
		return 2
	}
	dir := req.caseDir
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
		Kind:      req.kind,
		CaseID:    strings.TrimSpace(req.caseID),
		Authority: strings.TrimSpace(req.authority),
		Operator:  operator(),
		Report:    doc,
	})
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "saved %s\n", path)
	return 0
}

// operator names who ran the tool, for the audit log. It reads the login
// name from the environment and is best-effort: an empty value is fine.
func operator() string {
	for _, key := range []string{"FOOTPRINT_OPERATOR", "USER", "LOGNAME"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
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
