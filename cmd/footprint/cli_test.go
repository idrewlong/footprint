package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/idrewlong/footprint/pkg/casefile"
	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/report"
)

type fakeSite struct {
	name, domain, category, method string
	status                         checker.Status
}

func (f fakeSite) Name() string     { return f.name }
func (f fakeSite) Domain() string   { return f.domain }
func (f fakeSite) Category() string { return f.category }
func (f fakeSite) Method() string   { return f.method }
func (f fakeSite) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	res := checker.Result{Status: f.status, Duration: 5 * time.Millisecond}
	if f.status == checker.StatusFound {
		res.DeleteURL = "https://example.com/delete"
		res.SecurityURL = "https://example.com/security"
		res.Evidence = "Signup endpoint said this email is already registered."
	}
	return res
}

type fakeProfile struct {
	name, domain, category string
}

func (f fakeProfile) Name() string     { return f.name }
func (f fakeProfile) Domain() string   { return f.domain }
func (f fakeProfile) Category() string { return f.category }
func (f fakeProfile) Method() string   { return "profile" }
func (f fakeProfile) Check(ctx context.Context, c *http.Client, username string) checker.Result {
	return checker.Result{
		Status:     checker.StatusFound,
		ProfileURL: "https://" + f.domain + "/" + username,
		Evidence:   "Public profile exists for this username.",
		Detail:     "Octo Cat",
		Duration:   5 * time.Millisecond,
	}
}

func TestUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := execute(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(stderr.String(), "footprint scan") {
		t.Fatalf("usage missing:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("usage wrote to stdout")
	}
}

func TestSitesList(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"sites", "--category", "dev"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	text := stdout.String()
	if !strings.Contains(text, "github") || !strings.Contains(text, "replit") {
		t.Fatalf("dev list:\n%s", text)
	}
	if strings.Contains(text, "spotify") {
		t.Fatal("spotify listed under dev")
	}
}

func TestSitesUnknownCategory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"sites", "--category", "news"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown category") {
		t.Fatalf("stderr %s", stderr.String())
	}
}

func TestScanRejectsInvalidEmail(t *testing.T) {
	called := false
	catalog := func(categories, names []string) ([]checker.Site, error) {
		called = true
		return nil, nil
	}
	var stdout, stderr bytes.Buffer
	code := executeCatalog([]string{"scan", "not-an-email"}, &stdout, &stderr, catalog)
	if code != 2 {
		t.Fatalf("code %d", code)
	}
	if called {
		t.Fatal("invalid email still selected sites")
	}
}

func TestScanJSONOnlyFound(t *testing.T) {
	catalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeSite{name: "alpha", domain: "alpha.example", category: "dev", method: "register", status: checker.StatusFound},
			fakeSite{name: "beta", domain: "beta.example", category: "dev", method: "login", status: checker.StatusNotFound},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := executeCatalog([]string{"scan", "--json", "--only-found", "me@example.com"}, &stdout, &stderr, catalog)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, `"site": "alpha"`) {
		t.Fatalf("missing hit:\n%s", out)
	}
	if strings.Contains(out, `"site": "beta"`) {
		t.Fatal("only-found still listed a miss")
	}
	if !strings.Contains(out, `"not_found": 1`) || !strings.Contains(out, `"found": 1`) {
		t.Fatalf("summary dropped coverage:\n%s", out)
	}
	if !strings.Contains(out, `"duration_ms":`) {
		t.Fatal("duration missing")
	}
	if !strings.Contains(stderr.String(), "checking me@example.com across 2 sites") {
		t.Fatalf("stderr %s", stderr.String())
	}
}

func TestScanPrintsRows(t *testing.T) {
	catalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeSite{name: "alpha", domain: "alpha.example", category: "dev", method: "register", status: checker.StatusFound},
			fakeSite{name: "beta", domain: "beta.example", category: "dev", method: "login", status: checker.StatusNotFound},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := executeCatalog([]string{"scan", "me@example.com"}, &stdout, &stderr, catalog)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "●") || !strings.Contains(out, "alpha") || !strings.Contains(out, "dev") || !strings.Contains(out, "https://example.com/delete") {
		t.Fatalf("report missing:\n%s", out)
	}
	if strings.Contains(out, "SITE") || strings.Contains(out, "https://example.com/security") || strings.Contains(out, "METHOD") {
		t.Fatalf("terminal included extra fields:\n%s", out)
	}
	if !strings.Contains(out, "register · Signup endpoint said this email is already registered.") {
		t.Fatalf("terminal missing evidence:\n%s", out)
	}
	if strings.Contains(out, "beta") || strings.Contains(out, "not_found") {
		t.Fatalf("terminal listed a miss:\n%s", out)
	}
	if !strings.Contains(out, "1 found · 1 not found · 0 rate limited · 0 error") {
		t.Fatalf("summary dropped the miss:\n%s", out)
	}
	if strings.Contains(out, "{") {
		t.Fatal("default output was JSON")
	}
}

func TestScanEmailSkipsUsernames(t *testing.T) {
	emailCatalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeSite{name: "alpha", domain: "alpha.example", category: "dev", method: "register", status: checker.StatusFound},
		}, nil
	}
	profileCatalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeProfile{name: "asciinema", domain: "asciinema.org", category: "dev"},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := runCommand([]string{"scan", "email", "me@example.com", "--json"}, &stdout, &stderr, emailCatalog, profileCatalog)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, `"site": "alpha"`) || strings.Contains(out, `"site": "asciinema"`) || strings.Contains(out, `"username"`) {
		t.Fatalf("email scan included a username check:\n%s", out)
	}
	if strings.Contains(stderr.String(), "profiles") {
		t.Fatalf("stderr %s", stderr.String())
	}
}

func TestScanEmailAndUsername(t *testing.T) {
	emailCatalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeSite{name: "alpha", domain: "alpha.example", category: "dev", method: "register", status: checker.StatusFound},
		}, nil
	}
	profileCatalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeProfile{name: "asciinema", domain: "asciinema.org", category: "dev"},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := runCommand([]string{"scan", "username", "octocat", "email", "me@example.com", "--json"}, &stdout, &stderr, emailCatalog, profileCatalog)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, `"site": "alpha"`) || !strings.Contains(out, `"site": "asciinema"`) || !strings.Contains(out, "https://asciinema.org/octocat") {
		t.Fatalf("combined scan missing a target:\n%s", out)
	}
	if !strings.Contains(out, `"email": "me@example.com"`) || !strings.Contains(out, `"username": "octocat"`) {
		t.Fatalf("combined scan labels:\n%s", out)
	}
	if !strings.Contains(stderr.String(), "checking me@example.com and octocat across 1 site and 1 profile") {
		t.Fatalf("stderr %s", stderr.String())
	}
}

func TestScanUsername(t *testing.T) {
	emailCalled := false
	emailCatalog := func(categories, names []string) ([]checker.Site, error) {
		emailCalled = true
		return nil, nil
	}
	profileCatalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeProfile{name: "asciinema", domain: "asciinema.org", category: "dev"},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := runCommand([]string{"scan", "username", "octocat"}, &stdout, &stderr, emailCatalog, profileCatalog)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	if emailCalled {
		t.Fatal("username scan checked email sites")
	}
	out := stdout.String()
	if !strings.Contains(out, "https://asciinema.org/octocat") || !strings.Contains(out, "octocat") {
		t.Fatalf("username report:\n%s", out)
	}
	if strings.Contains(out, "@") {
		t.Fatalf("username report mentioned an email:\n%s", out)
	}
}

func TestScanMarkdownListsEveryStatus(t *testing.T) {
	catalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeSite{name: "alpha", domain: "alpha.example", category: "dev", method: "register", status: checker.StatusFound},
			fakeSite{name: "beta", domain: "beta.example", category: "dev", method: "login", status: checker.StatusNotFound},
			fakeSite{name: "gamma", domain: "gamma.example", category: "dev", method: "register", status: checker.StatusRateLimited},
			fakeSite{name: "delta", domain: "delta.example", category: "dev", method: "login", status: checker.StatusError},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := executeCatalog([]string{"scan", "--md", "me@example.com"}, &stdout, &stderr, catalog)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"**Bottom line:**",
		"## Findings",
		"| alpha | register | Signup endpoint said this email is already registered. |",
		"## Coverage",
		"## Actions",
		"https://example.com/security",
		"https://example.com/delete",
		"Unchecked:",
		"- **gamma** — rate limited",
		"- **delta** — error",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown missing %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "beta") {
		t.Fatalf("markdown listed a miss:\n%s", out)
	}
}

func TestScanAcceptsFlagsAfterEmail(t *testing.T) {
	catalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeSite{name: "alpha", domain: "alpha.example", category: "dev", method: "register", status: checker.StatusFound},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := executeCatalog([]string{"scan", "me@example.com", "--json", "--timeout", "5s"}, &stdout, &stderr, catalog)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"site": "alpha"`) {
		t.Fatalf("stdout %s", stdout.String())
	}
}

func TestUserJSONIncludesProfile(t *testing.T) {
	catalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeSite{name: "alpha", domain: "alpha.example", category: "dev", method: "profile", status: checker.StatusFound},
			fakeSite{name: "beta", domain: "beta.example", category: "dev", method: "profile", status: checker.StatusNotFound},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := runUser([]string{"--json", "octocat"}, &stdout, &stderr, catalog)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, `"site": "alpha"`) || !strings.Contains(out, `"site": "beta"`) || !strings.Contains(out, `"username": "octocat"`) {
		t.Fatalf("json missing a status:\n%s", out)
	}
	if strings.Contains(out, `"email"`) {
		t.Fatalf("username report labeled the query as an email:\n%s", out)
	}
}

func TestUserPrintsProfileLink(t *testing.T) {
	catalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeProfile{name: "alpha", domain: "alpha.example", category: "dev"},
			fakeSite{name: "beta", domain: "beta.example", category: "dev", method: "profile", status: checker.StatusNotFound},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := runUser([]string{"octocat"}, &stdout, &stderr, catalog)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "https://alpha.example/octocat") || !strings.Contains(out, "Octo Cat") {
		t.Fatalf("profile info missing:\n%s", out)
	}
	if strings.Contains(out, "beta") {
		t.Fatalf("terminal listed a miss:\n%s", out)
	}
}

func TestUserRejectsEmail(t *testing.T) {
	called := false
	catalog := func(categories, names []string) ([]checker.Site, error) {
		called = true
		return nil, nil
	}
	var stdout, stderr bytes.Buffer
	code := runUser([]string{"me@example.com"}, &stdout, &stderr, catalog)
	if code != 2 || called {
		t.Fatalf("code %d called %v stderr %s", code, called, stderr.String())
	}
}

func TestProgressPlainLine(t *testing.T) {
	var buf bytes.Buffer
	p := newProgress(&buf, false, "checking me@example.com across 2 sites", "me@example.com", 2)
	p.start()
	p.add(checker.StatusFound)
	p.finish()
	if buf.String() != "checking me@example.com across 2 sites\n" {
		t.Fatalf("progress %q", buf.String())
	}
}

func TestProgressOverwritesOnTTY(t *testing.T) {
	var buf bytes.Buffer
	p := newProgress(&buf, true, "checking me@example.com across 2 sites", "me@example.com", 2)
	p.start()
	p.add(checker.StatusFound)
	p.add(checker.StatusRateLimited)
	p.finish()
	out := buf.String()
	if !strings.Contains(out, "\r") || !strings.Contains(out, "2/2") || !strings.Contains(out, "1 found") || !strings.Contains(out, "1 rate limited") {
		t.Fatalf("progress %q", out)
	}
	if strings.Contains(out, "checking me@example.com across 2 sites") {
		t.Fatalf("live progress kept the static line: %q", out)
	}
}

func TestScanRejectsBothFormats(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := execute([]string{"scan", "--json", "--md", "me@example.com"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code %d", code)
	}
}

type fakeLookupDNS struct {
	mx       []*net.MX
	txt      map[string][]string
	addr     []string
	seenMX   []string
	seenTXT  []string
	seenAddr []string
	txtCalled bool
}

func (f *fakeLookupDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	f.seenMX = append(f.seenMX, name)
	return f.mx, nil
}

func (f *fakeLookupDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.txtCalled = true
	f.seenTXT = append(f.seenTXT, name)
	if f.txt == nil {
		return nil, nil
	}
	return f.txt[name], nil
}

func (f *fakeLookupDNS) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	f.seenAddr = append(f.seenAddr, addr)
	return f.addr, nil
}

func TestLookupDomainStripsMailbox(t *testing.T) {
	dns := &fakeLookupDNS{
		mx: []*net.MX{{Host: "mx.example.com.", Pref: 10}},
		txt: map[string][]string{
			"example.com":        {"v=spf1 mx -all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject"},
		},
	}
	deps := lookupDeps{DNS: dns, Disposable: map[string]struct{}{}}
	var stdout, stderr bytes.Buffer
	code := runLookup([]string{"domain", "ada@example.com"}, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	for _, name := range dns.seenMX {
		if name != "example.com" {
			t.Fatalf("MX lookup name %q", name)
		}
		if strings.Contains(name, "ada") {
			t.Fatalf("local-part sent: %q", name)
		}
	}
	for _, name := range dns.seenTXT {
		if strings.Contains(name, "ada") {
			t.Fatalf("local-part sent in TXT: %q", name)
		}
	}
	out := stdout.String()
	if !strings.Contains(out, "mx") || !strings.Contains(out, "MX records point at") {
		t.Fatalf("human missing mx evidence:\n%s", out)
	}
}

func TestLookupDomainCertsOptIn(t *testing.T) {
	dns := &fakeLookupDNS{
		mx:  []*net.MX{{Host: "mx.example.com.", Pref: 10}},
		txt: map[string][]string{"example.com": {"v=spf1 -all"}, "_dmarc.example.com": {"v=DMARC1; p=none"}},
	}
	var certCalls int
	get := func(ctx context.Context, url string) ([]byte, int, error) {
		certCalls++
		return []byte(`[{"common_name":"example.com"}]`), 200, nil
	}
	deps := lookupDeps{DNS: dns, HTTPGet: get, Disposable: map[string]struct{}{}}

	var stdout, stderr bytes.Buffer
	if code := runLookup([]string{"domain", "example.com"}, &stdout, &stderr, deps); code != 0 {
		t.Fatalf("without certs: code %d", code)
	}
	if certCalls != 0 {
		t.Fatalf("certs getter called without --certs: %d", certCalls)
	}

	stdout.Reset()
	stderr.Reset()
	if code := runLookup([]string{"domain", "example.com", "--certs"}, &stdout, &stderr, deps); code != 0 {
		t.Fatalf("with certs: code %d stderr %s", code, stderr.String())
	}
	if certCalls != 1 {
		t.Fatalf("certs getter calls = %d, want 1", certCalls)
	}
}

func TestLookupIPPrivateSkipsTXTAndHTTP(t *testing.T) {
	dns := &fakeLookupDNS{}
	httpCalled := false
	get := func(ctx context.Context, url string) ([]byte, int, error) {
		httpCalled = true
		return nil, 0, nil
	}
	deps := lookupDeps{DNS: dns, HTTPGet: get}
	var stdout, stderr bytes.Buffer
	code := runLookup([]string{"ip", "10.1.1.1"}, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	if dns.txtCalled {
		t.Fatal("TXT lookup was called for private IP")
	}
	if httpCalled {
		t.Fatal("HTTP getter was called for private IP")
	}
	if !strings.Contains(stdout.String(), "private address is not sent") {
		t.Fatalf("stdout missing private message:\n%s", stdout.String())
	}
}

func TestLookupIPInvalid(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runLookup([]string{"ip", "not-an-ip"}, &stdout, &stderr, lookupDeps{})
	if code != 2 {
		t.Fatalf("code %d", code)
	}
}

func TestLookupEntityRejectsEmailAndIP(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runLookup([]string{"entity", "someone@example.com"}, &stdout, &stderr, lookupDeps{}); code != 2 {
		t.Fatalf("email code %d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runLookup([]string{"entity", "8.8.8.8"}, &stdout, &stderr, lookupDeps{}); code != 2 {
		t.Fatalf("ip code %d", code)
	}
}

func TestLookupEntitySECAndOFAC(t *testing.T) {
	dir := t.TempDir()
	sdnPath := filepath.Join(dir, "sdn.csv")
	if err := os.WriteFile(sdnPath, []byte("123,Apple Inc.,Entity,SDGT,,,,,,,,,,\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secBody := []byte(`{"0":{"cik_str":320193,"ticker":"AAPL","title":"Apple Inc."}}`)
	deps := lookupDeps{
		SECFetch: staticFetcher{body: secBody, status: 200},
	}
	var stdout, stderr bytes.Buffer
	code := runLookup([]string{"entity", "Apple Inc.", "--sdn", sdnPath}, &stdout, &stderr, deps)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "SEC") || !strings.Contains(out, "OFAC") {
		t.Fatalf("stdout missing SEC/OFAC:\n%s", out)
	}
}

type staticFetcher struct {
	body   []byte
	status int
}

func (s staticFetcher) Get(ctx context.Context, url string) ([]byte, int, error) {
	return s.body, s.status, nil
}

func TestSuggestUsernameFromProfileURL(t *testing.T) {
	emailCatalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeProfileURL{
				name: "github", domain: "github.com", category: "dev", method: "register",
				status: checker.StatusFound, profileURL: "https://github.com/octocat",
			},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := runCommand([]string{"scan", "email", "me@example.com", "--json"}, &stdout, &stderr, emailCatalog, nil)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Next: footprint scan username octocat\n") {
		t.Fatalf("missing Next line:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "Next:") {
		t.Fatalf("Next leaked to stdout:\n%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	profileCatalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeProfile{name: "asciinema", domain: "asciinema.org", category: "dev"},
		}, nil
	}
	code = runCommand([]string{"scan", "email", "me@example.com", "username", "octocat", "--json"}, &stdout, &stderr, emailCatalog, profileCatalog)
	if code != 0 {
		t.Fatalf("with username: code %d stderr %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "Next:") {
		t.Fatalf("suggested username when one was already set:\n%s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	deepCatalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeProfileURL{
				name: "github", domain: "github.com", category: "dev", method: "register",
				status: checker.StatusFound, profileURL: "https://github.com/octocat/repo",
			},
		}, nil
	}
	code = runCommand([]string{"scan", "email", "me@example.com", "--json"}, &stdout, &stderr, deepCatalog, nil)
	if code != 0 {
		t.Fatalf("deep path: code %d stderr %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "Next:") {
		t.Fatalf("suggested username from a multi-segment path:\n%s", stderr.String())
	}
}

type fakeProfileURL struct {
	name, domain, category, method string
	status                         checker.Status
	profileURL                     string
}

func (f fakeProfileURL) Name() string     { return f.name }
func (f fakeProfileURL) Domain() string   { return f.domain }
func (f fakeProfileURL) Category() string { return f.category }
func (f fakeProfileURL) Method() string   { return f.method }
func (f fakeProfileURL) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	return checker.Result{
		Status:     f.status,
		ProfileURL: f.profileURL,
		Evidence:   "Signup endpoint said this email is already registered.",
		Duration:   5 * time.Millisecond,
	}
}

func TestScanSaveCaseFile(t *testing.T) {
	catalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeSite{name: "alpha", domain: "alpha.example", category: "dev", method: "register", status: checker.StatusFound},
		}, nil
	}
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := executeCatalog([]string{"scan", "email", "me@example.com", "--save", "--case-dir", dir}, &stdout, &stderr, catalog)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "alpha") {
		t.Fatalf("stdout missing report:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "saved ") {
		t.Fatalf("stderr missing saved path:\n%s", stderr.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("files in case dir: %d", len(entries))
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o, want 0600", info.Mode().Perm())
	}
}

func TestDiffUncheckedNotGone(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	writeSaved(t, oldPath, casefile.Saved{
		Kind: "identity",
		Report: report.Document{
			Email: "me@example.com",
			Results: []checker.Result{
				{Site: "zoom", Method: "register", Status: checker.StatusFound, Evidence: "zoom was found"},
				{Site: "slack", Method: "register", Status: checker.StatusFound, Evidence: "slack was found"},
			},
		},
	})
	writeSaved(t, newPath, casefile.Saved{
		Kind: "identity",
		Report: report.Document{
			Email: "me@example.com",
			Results: []checker.Result{
				{Site: "zoom", Method: "register", Status: checker.StatusRateLimited},
				{Site: "slack", Method: "register", Status: checker.StatusNotFound},
			},
		},
	})
	var stdout, stderr bytes.Buffer
	code := runDiff([]string{oldPath, newPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Unchecked") || !strings.Contains(out, "zoom") {
		t.Fatalf("missing Unchecked zoom:\n%s", out)
	}
	goneIdx := strings.Index(out, "Gone")
	uncheckedIdx := strings.Index(out, "Unchecked")
	if goneIdx < 0 || uncheckedIdx < 0 {
		t.Fatalf("missing sections:\n%s", out)
	}
	goneSection := out[goneIdx:uncheckedIdx]
	if strings.Contains(goneSection, "zoom") {
		t.Fatalf("zoom listed under Gone:\n%s", out)
	}
}

func TestNoteMergesEmailAndDomain(t *testing.T) {
	dir := t.TempDir()
	emailPath := filepath.Join(dir, "a.json")
	domainPath := filepath.Join(dir, "b.json")
	writeSaved(t, emailPath, casefile.Saved{
		Kind: "identity",
		Report: report.Document{
			Email: "me@example.com",
			Results: []checker.Result{
				{Site: "adobe", Method: "login", Status: checker.StatusFound, Evidence: "Sign-in said registered."},
			},
		},
	})
	writeSaved(t, domainPath, casefile.Saved{
		Kind: "domain",
		Report: report.Document{
			SubjectDomain: "example.com",
			Results: []checker.Result{
				{Site: "mx", Method: "dns", Status: checker.StatusFound, Evidence: "MX records point at mx.example.com."},
			},
		},
	})
	var stdout, stderr bytes.Buffer
	code := runNote([]string{emailPath, domainPath, "--md"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "adobe") || !strings.Contains(out, "mx") {
		t.Fatalf("note missing findings:\n%s", out)
	}
}

func writeSaved(t *testing.T, path string, saved casefile.Saved) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(saved); err != nil {
		t.Fatal(err)
	}
}
