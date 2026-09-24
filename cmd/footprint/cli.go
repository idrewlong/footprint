package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"time"

	"github.com/idrewlong/footprint/internal/httpx"
	"github.com/idrewlong/footprint/pkg/casefile"
	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/domain"
	"github.com/idrewlong/footprint/pkg/entity"
	"github.com/idrewlong/footprint/pkg/infra"
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
  footprint lookup domain <domain-or-email> [--certs] [--json|--md] [--save] [--case-dir path]
  footprint lookup ip <ip> [--geoip path] [--json|--md] [--save] [--case-dir path]
  footprint lookup entity <name> --sdn path [--json|--md] [--save] [--case-dir path]
  footprint diff <old.json> <new.json>
  footprint note <report.json>... [--json|--md]

Scan and user flags:
  --only-found        omit non-hits from a JSON or Markdown report
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

func runScan(args []string, stdout, stderr io.Writer, catalog, profilesCatalog catalogFunc) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		onlyFound   bool
		asJSON      bool
		asMarkdown  bool
		save        bool
		caseDir     string
		concurrency int
		timeout     time.Duration
		categories  stringList
		names       stringList
	)
	fs.BoolVar(&onlyFound, "only-found", false, "omit non-hits from JSON or Markdown")
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.BoolVar(&save, "save", false, "write the report under the case directory")
	fs.StringVar(&caseDir, "case-dir", "", "case directory")
	fs.IntVar(&concurrency, "concurrency", checker.DefaultConcurrency, "parallel checks")
	fs.DurationVar(&timeout, "timeout", checker.DefaultTimeout, "per-site timeout")
	fs.Var(&categories, "category", "category to check")
	fs.Var(&names, "site", "site to check")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals := splitArgs(args, map[string]bool{
		"only-found": true,
		"json":       true,
		"md":         true,
		"save":       true,
		"h":          true,
		"help":       true,
	}, map[string]bool{
		"concurrency": true,
		"timeout":     true,
		"category":    true,
		"site":        true,
		"case-dir":    true,
	})
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if asJSON && asMarkdown {
		fmt.Fprintln(stderr, "footprint: pass only one of --json or --md")
		return 2
	}
	if concurrency < 1 {
		fmt.Fprintln(stderr, "footprint: --concurrency must be at least 1")
		return 2
	}
	if timeout <= 0 {
		fmt.Fprintln(stderr, "footprint: --timeout must be greater than 0")
		return 2
	}
	emailRaw, usernameRaw, targetErr := parseScanTargets(positionals)
	if targetErr != "" {
		if targetErr == "usage" {
			fmt.Fprint(stderr, usage)
			return 2
		}
		fmt.Fprint(stderr, targetErr)
		return 2
	}
	var email string
	if emailRaw != "" {
		var ok bool
		email, ok = normalizeEmail(emailRaw)
		if !ok {
			fmt.Fprintln(stderr, "footprint: email address is not valid")
			return 2
		}
	}
	var username string
	if usernameRaw != "" {
		var ok bool
		username, ok = normalizeUsername(usernameRaw)
		if !ok {
			fmt.Fprintln(stderr, "footprint: username is not valid")
			return 2
		}
		if profilesCatalog == nil {
			fmt.Fprintln(stderr, "footprint: username scan is not available")
			return 2
		}
	}
	var selected []checker.Site
	if email != "" {
		var err error
		selected, err = catalog(categories, names)
		if err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 2
		}
	}
	var profileSites []checker.Site
	if username != "" {
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
	if len(selected) == 0 && len(profileSites) == 0 {
		fmt.Fprintln(stderr, "footprint: no sites matched")
		return 2
	}
	human := !asJSON && !asMarkdown
	var label string
	switch {
	case email != "" && username != "":
		label = fmt.Sprintf("checking %s and %s across %s and %s", email, username, counted(len(selected), "site", "sites"), counted(len(profileSites), "profile", "profiles"))
	case username != "":
		label = fmt.Sprintf("checking %s across %s", username, counted(len(profileSites), "profile", "profiles"))
	default:
		label = fmt.Sprintf("checking %s across %s", email, counted(len(selected), "site", "sites"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	prog := newProgress(stderr, human && isTerminal(stderr), label, scanSubject(email, username), len(selected)+len(profileSites))
	prog.start()
	start := time.Now()
	var results []checker.Result
	collect := func(query string, checks []checker.Site) {
		for res := range checker.Run(ctx, query, checks, checker.Options{Concurrency: concurrency, Timeout: timeout}) {
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
	var doc report.Document
	if email != "" {
		doc = report.Build(email, results, onlyFound && asJSON)
		doc.Username = username
	} else {
		doc = report.BuildUser(username, results, onlyFound && asJSON)
	}
	elapsed := time.Since(start)
	if err := writeReport(stdout, stderr, doc, asJSON, asMarkdown, start, elapsed); err != nil {
		return 1
	}
	if code := maybeSave(stderr, save, caseDir, "identity", doc, start, elapsed); code != 0 {
		return code
	}
	return 0
}

func runUser(args []string, stdout, stderr io.Writer, catalog catalogFunc) int {
	fs := flag.NewFlagSet("user", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		onlyFound   bool
		asJSON      bool
		asMarkdown  bool
		concurrency int
		timeout     time.Duration
		categories  stringList
		names       stringList
	)
	fs.BoolVar(&onlyFound, "only-found", false, "omit non-hits from JSON or Markdown")
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.IntVar(&concurrency, "concurrency", checker.DefaultConcurrency, "parallel checks")
	fs.DurationVar(&timeout, "timeout", checker.DefaultTimeout, "per-site timeout")
	fs.Var(&categories, "category", "category to check")
	fs.Var(&names, "site", "profile to check")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals := splitArgs(args, map[string]bool{
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
	})
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if asJSON && asMarkdown {
		fmt.Fprintln(stderr, "footprint: pass only one of --json or --md")
		return 2
	}
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
	for res := range checker.Run(ctx, username, selected, checker.Options{Concurrency: concurrency, Timeout: timeout}) {
		results = append(results, res)
		prog.add(res.Status)
	}
	prog.finish()
	doc := report.BuildUser(username, results, onlyFound && asJSON)
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

func toolVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	return info.Main.Version
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

func counted(n int, one, many string) string {
	word := many
	if n == 1 {
		word = one
	}
	return fmt.Sprintf("%d %s", n, word)
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

func matchCatalog(all func() []checker.Site) catalogFunc {
	return func(categories, names []string) ([]checker.Site, error) {
		return filterSites(all(), categories, names), nil
	}
}

func filterSites(all []checker.Site, categories, names []string) []checker.Site {
	catSet := make(map[string]struct{}, len(categories))
	for _, category := range categories {
		category = strings.ToLower(strings.TrimSpace(category))
		if category != "" {
			catSet[category] = struct{}{}
		}
	}
	nameSet := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			nameSet[name] = struct{}{}
		}
	}
	var out []checker.Site
	for _, site := range all {
		if len(catSet) > 0 {
			if _, ok := catSet[strings.ToLower(site.Category())]; !ok {
				continue
			}
		}
		if len(nameSet) > 0 {
			if _, ok := nameSet[strings.ToLower(site.Name())]; !ok {
				continue
			}
		}
		out = append(out, site)
	}
	return out
}

func missingNames(names []string, groups ...[]checker.Site) []string {
	have := map[string]struct{}{}
	for _, group := range groups {
		for _, site := range group {
			have[strings.ToLower(site.Name())] = struct{}{}
		}
	}
	var missing []string
	seen := map[string]struct{}{}
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		if _, ok := have[key]; ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		missing = append(missing, name)
	}
	return missing
}

func runSites(args []string, stdout, stderr io.Writer, catalog catalogFunc) int {
	fs := flag.NewFlagSet("sites", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		asJSON     bool
		categories stringList
	)
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.Var(&categories, "category", "category to list")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals := splitArgs(args, map[string]bool{
		"json": true,
		"h":    true,
		"help": true,
	}, map[string]bool{
		"category": true,
	})
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positionals) != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	selected, err := catalog(categories, nil)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	if asJSON {
		type row struct {
			Site     string `json:"site"`
			Domain   string `json:"domain"`
			Category string `json:"category"`
			Method   string `json:"method"`
		}
		rows := make([]row, 0, len(selected))
		for _, site := range selected {
			rows = append(rows, row{Site: site.Name(), Domain: site.Domain(), Category: site.Category(), Method: site.Method()})
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 1
		}
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "%-12s  %-16s  %-16s  %s\n", "SITE", "DOMAIN", "CATEGORY", "METHOD")
	for _, site := range selected {
		fmt.Fprintf(stdout, "%-12s  %-16s  %-16s  %s\n", site.Name(), site.Domain(), site.Category(), site.Method())
	}
	return 0
}

// lookupDNS is the combined DNS surface for domain and infra checks.
type lookupDNS interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// lookupDeps lets tests inject fakes so CLI tests never open the network.
type lookupDeps struct {
	DNS        lookupDNS
	HTTPGet    func(context.Context, string) ([]byte, int, error)
	SECFetch   entity.Fetcher
	Disposable map[string]struct{}
}

type netDNS struct{ r *net.Resolver }

func (n netDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return n.r.LookupMX(ctx, name)
}
func (n netDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return n.r.LookupTXT(ctx, name)
}
func (n netDNS) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return n.r.LookupAddr(ctx, addr)
}

type httpGetter struct {
	client *http.Client
	ua     string
}

func (h httpGetter) Get(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	if h.ua != "" {
		req.Header.Set("User-Agent", h.ua)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

type funcFetcher func(context.Context, string) ([]byte, int, error)

func (f funcFetcher) Get(ctx context.Context, url string) ([]byte, int, error) {
	return f(ctx, url)
}

func liveLookupDeps() lookupDeps {
	client := httpx.NewClient(httpx.Config{Timeout: checker.DefaultTimeout})
	get := httpGetter{client: client}.Get
	return lookupDeps{
		DNS:        netDNS{r: net.DefaultResolver},
		HTTPGet:    get,
		SECFetch:   httpGetter{client: client, ua: secUserAgent},
		Disposable: domain.BuiltinDisposable(),
	}
}

func runLookup(args []string, stdout, stderr io.Writer, deps lookupDeps) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "domain":
		return runLookupDomain(args[1:], stdout, stderr, deps)
	case "ip":
		return runLookupIP(args[1:], stdout, stderr, deps)
	case "entity":
		return runLookupEntity(args[1:], stdout, stderr, deps)
	default:
		fmt.Fprintf(stderr, "unknown lookup kind %q\n\n%s", args[0], usage)
		return 2
	}
}

func runLookupDomain(args []string, stdout, stderr io.Writer, deps lookupDeps) int {
	fs := flag.NewFlagSet("lookup domain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		certs      bool
		asJSON     bool
		asMarkdown bool
		save       bool
		caseDir    string
	)
	fs.BoolVar(&certs, "certs", false, "include crt.sh certificate count")
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.BoolVar(&save, "save", false, "write the report under the case directory")
	fs.StringVar(&caseDir, "case-dir", "", "case directory")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals := splitArgs(args, map[string]bool{
		"certs": true,
		"json":  true,
		"md":    true,
		"save":  true,
		"h":     true,
		"help":  true,
	}, map[string]bool{
		"case-dir": true,
	})
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if asJSON && asMarkdown {
		fmt.Fprintln(stderr, "footprint: pass only one of --json or --md")
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	query := positionals[0]
	host, err := domain.Host(query)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	dns := deps.DNS
	if dns == nil {
		dns = netDNS{r: net.DefaultResolver}
	}
	disposable := deps.Disposable
	if disposable == nil {
		disposable = domain.BuiltinDisposable()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	rows, err := domain.Check(ctx, dns, query, disposable)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	if certs {
		get := deps.HTTPGet
		if get == nil {
			get = httpGetter{client: httpx.NewClient(httpx.Config{Timeout: checker.DefaultTimeout})}.Get
		}
		rows = append(rows, domain.Certificates(ctx, get, host))
	}
	doc := report.Build("", rows, false)
	doc.SubjectDomain = host
	elapsed := time.Since(start)
	if err := writeReport(stdout, stderr, doc, asJSON, asMarkdown, start, elapsed); err != nil {
		return 1
	}
	return maybeSave(stderr, save, caseDir, "domain", doc, start, elapsed)
}

func runLookupIP(args []string, stdout, stderr io.Writer, deps lookupDeps) int {
	fs := flag.NewFlagSet("lookup ip", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		geoipPath  string
		asJSON     bool
		asMarkdown bool
		save       bool
		caseDir    string
	)
	fs.StringVar(&geoipPath, "geoip", "", "MaxMind GeoIP database path")
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.BoolVar(&save, "save", false, "write the report under the case directory")
	fs.StringVar(&caseDir, "case-dir", "", "case directory")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals := splitArgs(args, map[string]bool{
		"json": true,
		"md":   true,
		"save": true,
		"h":    true,
		"help": true,
	}, map[string]bool{
		"geoip":    true,
		"case-dir": true,
	})
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if asJSON && asMarkdown {
		fmt.Fprintln(stderr, "footprint: pass only one of --json or --md")
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ip := strings.TrimSpace(positionals[0])
	dns := deps.DNS
	if dns == nil {
		dns = netDNS{r: net.DefaultResolver}
	}
	var geo infra.GeoIP
	if geoipPath != "" {
		opened, err := infra.OpenGeoIP(geoipPath)
		if err != nil {
			fmt.Fprintf(stderr, "footprint: geoip: %v\n", err)
			return 2
		}
		geo = opened
	}
	var fetch infra.Fetcher
	if deps.HTTPGet != nil {
		fetch = funcFetcher(deps.HTTPGet)
	} else {
		fetch = httpGetter{client: httpx.NewClient(httpx.Config{Timeout: checker.DefaultTimeout})}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	rows, err := infra.Check(ctx, dns, geo, fetch, ip)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	doc := report.Build("", rows, false)
	doc.SubjectIP = ip
	elapsed := time.Since(start)
	if err := writeReport(stdout, stderr, doc, asJSON, asMarkdown, start, elapsed); err != nil {
		return 1
	}
	return maybeSave(stderr, save, caseDir, "infra", doc, start, elapsed)
}

func runLookupEntity(args []string, stdout, stderr io.Writer, deps lookupDeps) int {
	fs := flag.NewFlagSet("lookup entity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		sdnPath    string
		asJSON     bool
		asMarkdown bool
		save       bool
		caseDir    string
	)
	fs.StringVar(&sdnPath, "sdn", "", "local OFAC SDN CSV path")
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.BoolVar(&save, "save", false, "write the report under the case directory")
	fs.StringVar(&caseDir, "case-dir", "", "case directory")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals := splitArgs(args, map[string]bool{
		"json": true,
		"md":   true,
		"save": true,
		"h":    true,
		"help": true,
	}, map[string]bool{
		"sdn":      true,
		"case-dir": true,
	})
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if asJSON && asMarkdown {
		fmt.Fprintln(stderr, "footprint: pass only one of --json or --md")
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	name := positionals[0]
	if err := entity.Validate(name); err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	var records []entity.Record
	if sdnPath != "" {
		f, err := os.Open(sdnPath)
		if err != nil {
			records = nil
		} else {
			loaded, loadErr := entity.LoadSDN(f)
			f.Close()
			if loadErr != nil {
				records = nil
			} else {
				records = loaded
			}
		}
	}
	sec := deps.SECFetch
	if sec == nil {
		client := httpx.NewClient(httpx.Config{Timeout: checker.DefaultTimeout})
		sec = httpGetter{client: client, ua: secUserAgent}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	rows := []checker.Result{
		entity.Screen(name, records),
		entity.SEC(ctx, sec, name),
	}
	doc := report.Build("", rows, false)
	doc.SubjectEntity = name
	elapsed := time.Since(start)
	if err := writeReport(stdout, stderr, doc, asJSON, asMarkdown, start, elapsed); err != nil {
		return 1
	}
	return maybeSave(stderr, save, caseDir, "entity", doc, start, elapsed)
}

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals := splitArgs(args, map[string]bool{
		"h":    true,
		"help": true,
	}, nil)
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
	flags, positionals := splitArgs(args, map[string]bool{
		"json": true,
		"md":   true,
		"h":    true,
		"help": true,
	}, nil)
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
	start := time.Now()
	if err := writeReport(stdout, stderr, merged, asJSON, asMarkdown, start, 0); err != nil {
		return 1
	}
	return 0
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
// non-flag otherwise.
func splitArgs(args []string, boolFlags, valueFlags map[string]bool) (flags, positionals []string) {
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
					flags = append(flags, "")
					continue
				}
				i++
				flags = append(flags, args[i])
			}
		default:
			positionals = append(positionals, arg)
		}
	}
	return flags, positionals
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

type progress struct {
	w       io.Writer
	live    bool
	label   string
	query   string
	total   int
	done    int
	found   int
	limited int
	failed  int
	width   int
}

func newProgress(w io.Writer, live bool, label, query string, total int) *progress {
	return &progress{w: w, live: live, label: label, query: query, total: total}
}

func (p *progress) start() {
	if !p.live {
		fmt.Fprintln(p.w, p.label)
		return
	}
	p.render()
}

func (p *progress) add(status checker.Status) {
	p.done++
	switch status {
	case checker.StatusFound:
		p.found++
	case checker.StatusRateLimited:
		p.limited++
	case checker.StatusNotFound:
	default:
		p.failed++
	}
	if p.live {
		p.render()
	}
}

func (p *progress) render() {
	line := fmt.Sprintf("%s  %d/%d  %d found  %d rate limited  %d error", p.query, p.done, p.total, p.found, p.limited, p.failed)
	if len(line) < p.width {
		line += strings.Repeat(" ", p.width-len(line))
	}
	p.width = len(line)
	fmt.Fprintf(p.w, "\r%s", line)
}

func (p *progress) finish() {
	if !p.live {
		return
	}
	fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", p.width))
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func useColor(w io.Writer) bool {
	return isTerminal(w) && os.Getenv("NO_COLOR") == ""
}
