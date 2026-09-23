package profiles

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/idrewlong/footprint/pkg/checker"
)

func TestEveryProfileHasFixtures(t *testing.T) {
	hand := map[string]bool{
		"chess": true, "devto": true, "docker": true, "github": true,
		"hackernews": true, "huggingface": true, "lichess": true,
	}
	sites := All()
	if len(sites) < 200 {
		t.Fatalf("got %d profiles, want at least 200", len(sites))
	}
	for _, site := range sites {
		if !hand[site.Name()] {
			continue
		}
		for _, name := range []string{"found.http", "not_found.http", "rate_limited.http"} {
			path := filepath.Join("..", "..", "testdata", "profiles", site.Name(), name)
			info, err := os.Stat(path)
			if err != nil {
				t.Errorf("%s: %v", path, err)
				continue
			}
			if info.Size() == 0 {
				t.Errorf("%s is empty", path)
			}
		}
	}
}

func TestGithubProfile(t *testing.T)      { testProfile(t, "github") }
func TestLichessProfile(t *testing.T)     { testProfile(t, "lichess") }
func TestHuggingfaceProfile(t *testing.T) { testProfile(t, "huggingface") }
func TestDevtoProfile(t *testing.T)       { testProfile(t, "devto") }
func TestChessProfile(t *testing.T)       { testProfile(t, "chess") }
func TestHackernewsProfile(t *testing.T)  { testProfile(t, "hackernews") }
func TestDockerProfile(t *testing.T)      { testProfile(t, "docker") }

func TestInsaneJournalUnregisteredIsMiss(t *testing.T) {
	raw := "HTTP/1.1 200 OK\n\n<html><title>Error</title><h2>Unknown user</h2><p>The username <b>nobody</b> is not currently registered.</p></html>\n"
	res := checkRaw(t, "insanejournal", raw)
	if res.Status != checker.StatusNotFound || res.ProfileURL != "" {
		t.Fatalf("%+v", res)
	}
}

func TestProfileTextMentionStaysFound(t *testing.T) {
	raw := "HTTP/1.1 200 OK\n\n<html><title>Ada</title><p>People call me an unknown user.</p></html>\n"
	res := checkRaw(t, "insanejournal", raw)
	if res.Status != checker.StatusFound || res.ProfileURL == "" {
		t.Fatalf("%+v", res)
	}
}

func TestCatalogPageStatuses(t *testing.T) {
	name := catalogName(t)
	res := checkRaw(t, name, "HTTP/1.1 404 Not Found\n\nmissing\n")
	if res.Status != checker.StatusNotFound || res.ProfileURL != "" {
		t.Fatalf("%+v", res)
	}
	res = checkRaw(t, name, "HTTP/1.1 200 OK\n\n<html><title>Ada</title></html>\n")
	if res.Status != checker.StatusFound || res.ProfileURL == "" {
		t.Fatalf("%+v", res)
	}
	res = checkRaw(t, name, "HTTP/1.1 200 OK\n\n<html><title>Page not found</title></html>\n")
	if res.Status != checker.StatusNotFound {
		t.Fatalf("%+v", res)
	}
	res = checkRaw(t, name, "HTTP/1.1 200 OK\n\n<html><title>Sign up</title></html>\n")
	if res.Status != checker.StatusError {
		t.Fatalf("%+v", res)
	}
	res = checkRaw(t, name, "HTTP/1.1 429 Too Many Requests\n\ntoo many requests\n")
	if res.Status != checker.StatusRateLimited {
		t.Fatalf("%+v", res)
	}
}

func catalogName(t *testing.T) string {
	t.Helper()
	hand := map[string]bool{
		"chess": true, "devto": true, "docker": true, "github": true,
		"hackernews": true, "huggingface": true, "lichess": true,
	}
	for _, site := range All() {
		if !hand[site.Name()] {
			return site.Name()
		}
	}
	t.Fatal("catalog is empty")
	return ""
}

func TestGithubShowsDisplayName(t *testing.T) {
	res := checkFile(t, "github", "found.http")
	if res.Detail != "The Octocat" {
		t.Fatalf("detail %q", res.Detail)
	}
	if strings.Contains(res.Detail, "San Francisco") || strings.Contains(res.Detail, "octocat@") || strings.Contains(res.Detail, "@github") {
		t.Fatalf("private fields leaked into detail %q", res.Detail)
	}
	if res.ProfileURL != "https://github.com/nobody" {
		t.Fatalf("profile %q", res.ProfileURL)
	}
}

func TestDockerIgnoresPrivateFields(t *testing.T) {
	res := checkFile(t, "docker", "found.http")
	if res.Detail != "Andrew" {
		t.Fatalf("detail %q", res.Detail)
	}
	if strings.Contains(res.Detail, "Austin") || strings.Contains(res.Detail, "hidden@") {
		t.Fatalf("private fields leaked into detail %q", res.Detail)
	}
}

func TestHuggingfaceFollowsCaseRedirect(t *testing.T) {
	raw := "HTTP/1.1 307 Temporary Redirect\nLocation: /api/users/Nobody/overview\n\n<p>Temporary Redirect</p>\n---\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"_id\":\"abc\",\"fullname\":\"Vance\",\"numModels\":4}\n"
	res := checkRaw(t, "huggingface", raw)
	if res.Status != checker.StatusFound || res.Detail != "Vance" || res.ProfileURL != "https://huggingface.co/Nobody" {
		t.Fatalf("%+v", res)
	}
}

func TestHuggingfaceStrangeRedirectIsError(t *testing.T) {
	raw := "HTTP/1.1 307 Temporary Redirect\nLocation: https://example.com/login\n\n"
	res := checkRaw(t, "huggingface", raw)
	if res.Status != checker.StatusError {
		t.Fatalf("status %s", res.Status)
	}
}

func TestDockerOrgIsFound(t *testing.T) {
	raw := "HTTP/1.1 308 Permanent Redirect\nLocation: https://hub.docker.com/v2/orgs/moby\n\n"
	res := checkRaw(t, "docker", raw)
	if res.Status != checker.StatusFound {
		t.Fatalf("status %s", res.Status)
	}
}

func TestDockerStrangeRedirectIsError(t *testing.T) {
	raw := "HTTP/1.1 308 Permanent Redirect\nLocation: https://example.com/login\n\n"
	res := checkRaw(t, "docker", raw)
	if res.Status != checker.StatusError {
		t.Fatalf("status %s", res.Status)
	}
}

func testProfile(t *testing.T, name string) {
	t.Helper()
	cases := []struct {
		file string
		want checker.Status
	}{
		{"found.http", checker.StatusFound},
		{"not_found.http", checker.StatusNotFound},
		{"rate_limited.http", checker.StatusRateLimited},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			res := checkFile(t, name, tc.file)
			if res.Status != tc.want {
				t.Fatalf("status %s detail %q", res.Status, res.Detail)
			}
			if tc.want == checker.StatusFound && res.ProfileURL == "" {
				t.Fatal("found profile missing url")
			}
			if tc.want != checker.StatusFound && res.ProfileURL != "" {
				t.Fatalf("non-hit included profile url %q", res.ProfileURL)
			}
			if res.Method != "profile" || res.Site != name {
				t.Fatalf("metadata %+v", res)
			}
			if (tc.want == checker.StatusFound || tc.want == checker.StatusNotFound) && strings.TrimSpace(res.Evidence) == "" {
				t.Fatal("decisive result missing evidence")
			}
			if tc.want == checker.StatusRateLimited && res.Evidence != "" {
				t.Fatalf("rate limited included evidence %q", res.Evidence)
			}
		})
	}
}

func checkFile(t *testing.T, name, file string) checker.Result {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "profiles", name, file))
	if err != nil {
		t.Fatal(err)
	}
	return checkRaw(t, name, string(body))
}

func checkRaw(t *testing.T, name, raw string) checker.Result {
	t.Helper()
	client := clientFor(t, splitFixture(raw)...)
	return byName(t, name).Check(context.Background(), client, "nobody")
}

func byName(t *testing.T, name string) checker.Site {
	t.Helper()
	for _, site := range All() {
		if site.Name() == name {
			return site
		}
	}
	t.Fatalf("profile %s is not registered", name)
	return nil
}

func splitFixture(raw string) []string {
	parts := strings.Split(raw, "\n---\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

type rewrite struct {
	target *url.URL
	base   http.RoundTripper
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = r.target.Scheme
	cloned.URL.Host = r.target.Host
	base := r.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(cloned)
}

func clientFor(t *testing.T, messages ...string) *http.Client {
	t.Helper()
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n >= len(messages) {
			http.Error(w, "unexpected extra request", http.StatusInternalServerError)
			return
		}
		writeRaw(w, messages[n])
		n++
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: rewrite{target: target, base: srv.Client().Transport},
		Timeout:   0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func writeRaw(w http.ResponseWriter, raw string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, _ := strings.Cut(raw, "\n\n")
	lines := strings.Split(head, "\n")
	status := http.StatusOK
	if len(lines) > 0 {
		fields := strings.Fields(lines[0])
		if len(fields) >= 2 {
			if code, err := strconv.Atoi(fields[1]); err == nil {
				status = code
			}
		}
	}
	header := w.Header()
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if strings.EqualFold(key, "Content-Length") || strings.EqualFold(key, "Transfer-Encoding") {
			continue
		}
		header.Add(key, strings.TrimSpace(value))
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
