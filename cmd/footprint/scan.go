package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/report"
)

func runScan(args []string, stdout, stderr io.Writer, catalog, profilesCatalog catalogFunc) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		onlyFound   bool
		asJSON      bool
		asMarkdown  bool
		save        bool
		caseDir     string
		caseID      string
		authority   string
		allowNotify bool
		proxyURL    string
		batchFile   string
		concurrency int
		timeout     time.Duration
		categories  stringList
		names       stringList
	)
	fs.BoolVar(&onlyFound, "only-found", false, "omit non-hits from a JSON report")
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.BoolVar(&save, "save", false, "write the report under the case directory")
	fs.StringVar(&caseDir, "case-dir", "", "case directory")
	fs.StringVar(&caseID, "case-id", "", "case identifier recorded with a saved report")
	fs.StringVar(&authority, "authority", "", "legal authority recorded with a saved report")
	fs.BoolVar(&allowNotify, "allow-notify", false, "include checks that email the target (password reset)")
	fs.StringVar(&proxyURL, "proxy", "", "route checks through a proxy (http, https, socks5, socks5h)")
	fs.StringVar(&batchFile, "batch", "", "read subjects (one per line) from a file")
	fs.IntVar(&concurrency, "concurrency", checker.DefaultConcurrency, "parallel checks")
	fs.DurationVar(&timeout, "timeout", checker.DefaultTimeout, "per-site timeout")
	fs.Var(&categories, "category", "category to check")
	fs.Var(&names, "site", "site to check")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"only-found":   true,
		"json":         true,
		"md":           true,
		"save":         true,
		"allow-notify": true,
		"h":            true,
		"help":         true,
	}, map[string]bool{
		"concurrency": true,
		"timeout":     true,
		"category":    true,
		"site":        true,
		"case-dir":    true,
		"case-id":     true,
		"authority":   true,
		"proxy":       true,
		"batch":       true,
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
	// A batch reads subjects from a file. The positional names the kind
	// ("email" or "username") and every line is one subject of that kind.
	var (
		email, username string
		subjects        []string
		batchKind       string
		wantEmail       bool
		wantUser        bool
	)
	if batchFile != "" {
		if len(positionals) != 1 || (positionals[0] != "email" && positionals[0] != "username") {
			fmt.Fprintln(stderr, "footprint: --batch needs a kind: footprint scan email --batch <file> (or username)")
			return 2
		}
		batchKind = positionals[0]
		loaded, err := readSubjects(batchFile)
		if err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 2
		}
		if len(loaded) == 0 {
			fmt.Fprintf(stderr, "footprint: no subjects in %s\n", batchFile)
			return 2
		}
		subjects = loaded
		wantEmail = batchKind == "email"
		wantUser = batchKind == "username"
	} else {
		emailRaw, usernameRaw, targetErr := parseScanTargets(positionals)
		if targetErr != "" {
			if targetErr == "usage" {
				fmt.Fprint(stderr, usage)
				return 2
			}
			fmt.Fprint(stderr, targetErr)
			return 2
		}
		if emailRaw != "" {
			var ok bool
			email, ok = normalizeEmail(emailRaw)
			if !ok {
				fmt.Fprintln(stderr, "footprint: email address is not valid")
				return 2
			}
		}
		if usernameRaw != "" {
			var ok bool
			username, ok = normalizeUsername(usernameRaw)
			if !ok {
				fmt.Fprintln(stderr, "footprint: username is not valid")
				return 2
			}
		}
		wantEmail = email != ""
		wantUser = username != ""
	}
	if wantUser && profilesCatalog == nil {
		fmt.Fprintln(stderr, "footprint: username scan is not available")
		return 2
	}
	var selected []checker.Site
	if wantEmail {
		var err error
		selected, err = catalog(categories, names)
		if err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 2
		}
	}
	var profileSites []checker.Site
	if wantUser {
		var err error
		profileSites, err = profilesCatalog(categories, names)
		if err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 2
		}
	}
	if len(names) > 0 {
		if missing := missingNames(names, selected, profileSites); len(missing) > 0 {
			fmt.Fprintf(stderr, "footprint: unknown site %q\n", strings.Join(missing, ", "))
			return 2
		}
	}
	// Passive by default: a password-reset check can email the address under
	// investigation, which would alert the subject. Those checks run only
	// when the operator opts in with --allow-notify.
	if selected != nil {
		passive, alerting := splitNotify(selected)
		if !allowNotify {
			selected = passive
			if len(alerting) > 0 {
				fmt.Fprintf(stderr, "footprint: skipping %s that would email the target; pass --allow-notify to include %s (%s)\n",
					counted(len(alerting), "check", "checks"),
					counted(len(alerting), "it", "them"),
					notifyNames(alerting))
			}
		}
	}
	if len(selected) == 0 && len(profileSites) == 0 {
		fmt.Fprintln(stderr, "footprint: no sites matched")
		return 2
	}
	human := !asJSON && !asMarkdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	saveReq := saveRequest{save: save, caseDir: caseDir, kind: "identity", caseID: caseID, authority: authority}

	// runOne scans a single subject and returns its full scored report. The
	// site set is shared across subjects; only the subject changes, so a
	// batch reuses everything but the query.
	runOne := func(email, username string) (report.Document, []checker.Result, time.Time, time.Duration) {
		var label string
		switch {
		case email != "" && username != "":
			label = fmt.Sprintf("checking %s and %s across %s and %s", email, username, counted(len(selected), "site", "sites"), counted(len(profileSites), "profile", "profiles"))
		case username != "":
			label = fmt.Sprintf("checking %s across %s", username, counted(len(profileSites), "profile", "profiles"))
		default:
			label = fmt.Sprintf("checking %s across %s", email, counted(len(selected), "site", "sites"))
		}
		prog := newProgress(stderr, human && isTerminal(stderr), label, scanSubject(email, username), len(selected)+len(profileSites))
		prog.start()
		start := time.Now()
		var results []checker.Result
		collect := func(query string, checks []checker.Site) {
			for res := range checker.Run(ctx, query, checks, checker.Options{Concurrency: concurrency, Timeout: timeout, Transport: transport}) {
				results = append(results, res)
				prog.add(res.Status)
			}
		}
		if len(selected) > 0 {
			collect(email, selected)
		}
		if len(profileSites) > 0 {
			collect(username, profileSites)
		}
		prog.finish()
		var full report.Document
		if email != "" {
			full = report.Build(email, results, false)
			full.Username = username
		} else {
			full = report.BuildUser(username, results, false)
		}
		report.ScoreConfidence(&full)
		return full, results, start, time.Since(start)
	}

	if len(subjects) > 0 {
		return runScanBatch(ctx, stdout, stderr, subjects, batchKind, runOne, asJSON, asMarkdown, saveReq)
	}

	full, results, start, elapsed := runOne(email, username)
	doc := full
	if onlyFound && asJSON {
		if email != "" {
			doc = report.Build(email, results, true)
			doc.Username = username
		} else {
			doc = report.BuildUser(username, results, true)
		}
		report.ScoreConfidence(&doc)
	}
	if err := writeReport(stdout, stderr, doc, asJSON, asMarkdown, start, elapsed); err != nil {
		return 1
	}
	if suggested := suggestUsername(results, username); suggested != "" {
		fmt.Fprintf(stderr, "Next: footprint scan username %s\n", suggested)
	}
	if code := maybeSave(stderr, saveReq, full, start, elapsed); code != 0 {
		return code
	}
	return 0
}

func suggestUsername(results []checker.Result, username string) string {
	if username != "" {
		return ""
	}
	for _, res := range results {
		if res.Status != checker.StatusFound || res.ProfileURL == "" {
			continue
		}
		u, err := url.Parse(res.ProfileURL)
		if err != nil {
			continue
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) != 1 || parts[0] == "" || strings.Contains(parts[0], ".") {
			continue
		}
		return parts[0]
	}
	return ""
}

func parseScanTargets(positionals []string) (email, username, errMsg string) {
	if len(positionals) == 0 {
		return "", "", "usage"
	}
	// A bare address stays email-only. Username checks require the keyword.
	if len(positionals) == 1 && positionals[0] != "email" && positionals[0] != "username" {
		return positionals[0], "", ""
	}
	for i := 0; i < len(positionals); i++ {
		kind := positionals[i]
		if kind != "email" && kind != "username" {
			return "", "", fmt.Sprintf("footprint: unexpected %q\n", kind)
		}
		if i+1 >= len(positionals) || positionals[i+1] == "email" || positionals[i+1] == "username" {
			return "", "", fmt.Sprintf("footprint: %s needs a value\n", kind)
		}
		i++
		switch kind {
		case "email":
			if email != "" {
				return "", "", "footprint: email was given twice\n"
			}
			email = positionals[i]
		case "username":
			if username != "" {
				return "", "", "footprint: username was given twice\n"
			}
			username = positionals[i]
		}
	}
	return email, username, ""
}

func scanSubject(email, username string) string {
	if email != "" && username != "" {
		return email + " · " + username
	}
	if username != "" {
		return username
	}
	return email
}

func normalizeEmail(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t<>") {
		return "", false
	}
	addr, err := mail.ParseAddress(raw)
	if err != nil || addr.Address != raw {
		return "", false
	}
	at := strings.LastIndex(addr.Address, "@")
	if at <= 0 || at == len(addr.Address)-1 {
		return "", false
	}
	domain := addr.Address[at+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", false
	}
	return addr.Address, true
}
