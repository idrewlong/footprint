package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/idrewlong/footprint/internal/httpx"
	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/domain"
	"github.com/idrewlong/footprint/pkg/entity"
	"github.com/idrewlong/footprint/pkg/infra"
	"github.com/idrewlong/footprint/pkg/report"
)

// lookupDNS is the combined DNS surface for domain and infra checks.
type lookupDNS interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// lookupDeps lets tests inject fakes so CLI tests never open the network.
type lookupDeps struct {
	DNS     lookupDNS
	HTTPGet func(context.Context, string) ([]byte, int, error)
	// RDAPGet follows redirects: rdap.org answers with a redirect to the
	// regional registry. Nil falls back to HTTPGet.
	RDAPGet func(context.Context, string) ([]byte, int, error)
	// RangeGet downloads the published IP range lists. Nil skips them, so
	// tests never touch the network or the user's cache.
	RangeGet   func(context.Context, string) ([]byte, int, error)
	RangeDir   string
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

func (n netDNS) LookupHost(ctx context.Context, host string) ([]string, error) {
	return n.r.LookupHost(ctx, host)
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
	rangeDir := ""
	if dir, err := os.UserCacheDir(); err == nil {
		rangeDir = filepath.Join(dir, "footprint", "ranges")
	}
	return lookupDeps{
		DNS:        netDNS{r: net.DefaultResolver},
		HTTPGet:    get,
		RDAPGet:    httpGetter{client: followingClient(checker.DefaultTimeout)}.Get,
		RangeGet:   httpGetter{client: followingClient(rangeTimeout)}.Get,
		RangeDir:   rangeDir,
		SECFetch:   httpGetter{client: client, ua: secUserAgent},
		Disposable: domain.BuiltinDisposable(),
	}
}

// rangeTimeout covers downloading every range list; the largest are a few MB.
const rangeTimeout = 60 * time.Second

// followingClient follows up to five HTTPS redirects. rdap.org and some
// range lists answer with a redirect.
func followingClient(timeout time.Duration) *http.Client {
	client := httpx.NewClient(httpx.Config{Timeout: timeout})
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("redirect is not https")
		}
		return nil
	}
	return client
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
		caseID     string
		authority  string
		timeout    time.Duration
	)
	fs.BoolVar(&certs, "certs", false, "include crt.sh certificate count")
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.BoolVar(&save, "save", false, "write the report under the case directory")
	fs.StringVar(&caseDir, "case-dir", "", "case directory")
	fs.StringVar(&caseID, "case-id", "", "case identifier recorded with a saved report")
	fs.StringVar(&authority, "authority", "", "legal authority recorded with a saved report")
	fs.DurationVar(&timeout, "timeout", checker.DefaultTimeout, "lookup timeout")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"certs": true,
		"json":  true,
		"md":    true,
		"save":  true,
		"h":     true,
		"help":  true,
	}, map[string]bool{
		"case-dir":  true,
		"case-id":   true,
		"authority": true,
		"timeout":   true,
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
	if timeout <= 0 {
		fmt.Fprintln(stderr, "footprint: --timeout must be greater than 0")
		return 2
	}
	// Refuse before any lookup leaves the machine, as scan does.
	if save && (strings.TrimSpace(caseID) == "" || strings.TrimSpace(authority) == "") {
		fmt.Fprintln(stderr, "footprint: --save requires --case-id and --authority")
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
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	rows, err := domain.Check(ctx, dns, query, disposable)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	if certs {
		get := deps.HTTPGet
		if get == nil {
			get = httpGetter{client: httpx.NewClient(httpx.Config{Timeout: timeout})}.Get
		}
		rows = append(rows, domain.Certificates(ctx, get, host))
	}
	doc := report.Build("", rows, false)
	doc.SubjectDomain = host
	elapsed := time.Since(start)
	if err := writeReport(stdout, stderr, doc, asJSON, asMarkdown, start, elapsed); err != nil {
		return 1
	}
	return maybeSave(stderr, saveRequest{save: save, caseDir: caseDir, kind: "domain", caseID: caseID, authority: authority}, doc, start, elapsed)
}

func runLookupIP(args []string, stdout, stderr io.Writer, deps lookupDeps) int {
	fs := flag.NewFlagSet("lookup ip", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		geoipPath  string
		noUpdate   bool
		asJSON     bool
		asMarkdown bool
		save       bool
		caseDir    string
		caseID     string
		authority  string
		timeout    time.Duration
	)
	fs.StringVar(&geoipPath, "geoip", "", "MaxMind GeoIP database path")
	fs.BoolVar(&noUpdate, "no-update", false, "use cached range lists without downloading")
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.BoolVar(&save, "save", false, "write the report under the case directory")
	fs.StringVar(&caseDir, "case-dir", "", "case directory")
	fs.StringVar(&caseID, "case-id", "", "case identifier recorded with a saved report")
	fs.StringVar(&authority, "authority", "", "legal authority recorded with a saved report")
	fs.DurationVar(&timeout, "timeout", checker.DefaultTimeout, "lookup timeout")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"json":      true,
		"md":        true,
		"save":      true,
		"no-update": true,
		"h":         true,
		"help":      true,
	}, map[string]bool{
		"geoip":     true,
		"case-dir":  true,
		"case-id":   true,
		"authority": true,
		"timeout":   true,
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
	if timeout <= 0 {
		fmt.Fprintln(stderr, "footprint: --timeout must be greater than 0")
		return 2
	}
	// Refuse before any lookup leaves the machine, as scan does.
	if save && (strings.TrimSpace(caseID) == "" || strings.TrimSpace(authority) == "") {
		fmt.Fprintln(stderr, "footprint: --save requires --case-id and --authority")
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
	if deps.RDAPGet != nil {
		fetch = funcFetcher(deps.RDAPGet)
	} else if deps.HTTPGet != nil {
		fetch = funcFetcher(deps.HTTPGet)
	} else {
		fetch = httpGetter{client: httpx.NewClient(httpx.Config{Timeout: timeout})}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	var ranges *infra.RangeSet
	// Range lists are only for public addresses, and are read before the
	// lookup timeout starts because a first download can take longer.
	if deps.RangeGet != nil && infra.IsPublic(ip) {
		rctx, rcancel := context.WithTimeout(ctx, rangeTimeout)
		cache := infra.RangeCache{Dir: deps.RangeDir, Fetch: funcFetcher(deps.RangeGet), Update: !noUpdate}
		set := cache.LoadRanges(rctx, infra.DefaultRangeSources())
		rcancel()
		ranges = &set
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	profile, rows, err := infra.Lookup(ctx, infra.Sources{DNS: dns, GeoIP: geo, Fetch: fetch, Ranges: ranges}, ip)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	doc := report.Build("", rows, false)
	doc.SubjectIP = ip
	doc.IP = &profile
	elapsed := time.Since(start)
	if err := writeReport(stdout, stderr, doc, asJSON, asMarkdown, start, elapsed); err != nil {
		return 1
	}
	return maybeSave(stderr, saveRequest{save: save, caseDir: caseDir, kind: "infra", caseID: caseID, authority: authority}, doc, start, elapsed)
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
		caseID     string
		authority  string
		timeout    time.Duration
	)
	fs.StringVar(&sdnPath, "sdn", "", "local OFAC SDN CSV path")
	fs.BoolVar(&asJSON, "json", false, "write JSON to stdout")
	fs.BoolVar(&asMarkdown, "md", false, "write Markdown to stdout")
	fs.BoolVar(&save, "save", false, "write the report under the case directory")
	fs.StringVar(&caseDir, "case-dir", "", "case directory")
	fs.StringVar(&caseID, "case-id", "", "case identifier recorded with a saved report")
	fs.StringVar(&authority, "authority", "", "legal authority recorded with a saved report")
	fs.DurationVar(&timeout, "timeout", checker.DefaultTimeout, "lookup timeout")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"json": true,
		"md":   true,
		"save": true,
		"h":    true,
		"help": true,
	}, map[string]bool{
		"sdn":       true,
		"case-dir":  true,
		"case-id":   true,
		"authority": true,
		"timeout":   true,
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
	if timeout <= 0 {
		fmt.Fprintln(stderr, "footprint: --timeout must be greater than 0")
		return 2
	}
	// Refuse before any lookup leaves the machine, as scan does.
	if save && (strings.TrimSpace(caseID) == "" || strings.TrimSpace(authority) == "") {
		fmt.Fprintln(stderr, "footprint: --save requires --case-id and --authority")
		return 2
	}
	if len(positionals) != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	name := strings.TrimSpace(positionals[0])
	if err := entity.Validate(name); err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	ofac := entity.Screen(name, nil)
	if sdnPath != "" {
		f, err := os.Open(sdnPath)
		if err != nil {
			fmt.Fprintf(stderr, "footprint: sdn: %v\n", err)
			ofac = checker.Result{
				Site:     "ofac",
				Domain:   name,
				Category: "entity",
				Method:   "entity",
				Status:   checker.StatusError,
				Detail:   "failed to open SDN list",
			}
		} else {
			loaded, loadErr := entity.LoadSDN(f)
			closeErr := f.Close()
			if loadErr != nil {
				fmt.Fprintf(stderr, "footprint: sdn: %v\n", loadErr)
				ofac = checker.Result{
					Site:     "ofac",
					Domain:   name,
					Category: "entity",
					Method:   "entity",
					Status:   checker.StatusError,
					Detail:   "failed to load SDN list",
				}
			} else if closeErr != nil {
				fmt.Fprintf(stderr, "footprint: sdn: %v\n", closeErr)
				ofac = checker.Result{
					Site:     "ofac",
					Domain:   name,
					Category: "entity",
					Method:   "entity",
					Status:   checker.StatusError,
					Detail:   "failed to load SDN list",
				}
			} else {
				ofac = entity.Screen(name, loaded)
			}
		}
	}
	sec := deps.SECFetch
	if sec == nil {
		client := httpx.NewClient(httpx.Config{Timeout: timeout})
		sec = httpGetter{client: client, ua: secUserAgent}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	rows := []checker.Result{
		ofac,
		entity.SEC(ctx, sec, name),
	}
	doc := report.Build("", rows, false)
	doc.SubjectEntity = name
	elapsed := time.Since(start)
	if err := writeReport(stdout, stderr, doc, asJSON, asMarkdown, start, elapsed); err != nil {
		return 1
	}
	return maybeSave(stderr, saveRequest{save: save, caseDir: caseDir, kind: "entity", caseID: caseID, authority: authority}, doc, start, elapsed)
}
