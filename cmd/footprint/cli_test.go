package main

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
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
	if code := execute([]string{"sites", "--category", "shopping"}, &stdout, &stderr); code != 2 {
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
	if strings.Contains(out, "SITE") || strings.Contains(out, "https://example.com/security") || strings.Contains(out, "METHOD") || strings.Contains(out, "register") {
		t.Fatalf("terminal included extra fields:\n%s", out)
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
	for _, name := range []string{"alpha", "beta", "gamma", "delta", "## Not found", "## Rate limited", "## Error"} {
		if !strings.Contains(out, name) {
			t.Fatalf("markdown missing %s:\n%s", name, out)
		}
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
