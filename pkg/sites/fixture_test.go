package sites

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

func TestEverySiteHasFixtures(t *testing.T) {
	sites := All()
	if len(sites) < 15 {
		t.Fatalf("got %d sites, want at least 15", len(sites))
	}
	for _, site := range sites {
		for _, name := range []string{"found.http", "not_found.http", "rate_limited.http"} {
			path := filepath.Join("..", "..", "testdata", site.Name(), name)
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

func TestAdobe(t *testing.T)       { testSite(t, "adobe") }
func TestChess(t *testing.T)       { testSite(t, "chess") }
func TestDiscord(t *testing.T)     { testSite(t, "discord") }
func TestDropbox(t *testing.T)     { testSite(t, "dropbox") }
func TestDuolingo(t *testing.T)    { testSite(t, "duolingo") }
func TestFirefox(t *testing.T)     { testSite(t, "firefox") }
func TestGithub(t *testing.T)      { testSite(t, "github") }
func TestGravatar(t *testing.T)    { testSite(t, "gravatar") }
func TestInstagram(t *testing.T)   { testSite(t, "instagram") }
func TestLastfm(t *testing.T)      { testSite(t, "lastfm") }
func TestMicrosoft(t *testing.T)   { testSite(t, "microsoft") }
func TestReplit(t *testing.T)      { testSite(t, "replit") }
func TestSlack(t *testing.T)       { testSite(t, "slack") }
func TestSpotify(t *testing.T)     { testSite(t, "spotify") }
func TestTwitch(t *testing.T)      { testSite(t, "twitch") }
func TestX(t *testing.T)           { testSite(t, "x") }
func TestXposedOrNot(t *testing.T) { testSite(t, "xposedornot") }
func TestLeakCheck(t *testing.T)   { testSite(t, "leakcheck") }

func TestHIBP(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "test-key")
	testSite(t, "hibp")
}

func TestHIBPMissingKey(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "")
	res := (&hibp{}).Check(context.Background(), nil, "nobody@example.com")
	if res.Status != checker.StatusError || !strings.Contains(res.Detail, "api key") {
		t.Fatalf("%+v", res)
	}
}

func TestHIBPListsNamesOnly(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "test-key")
	res := checkRaw(t, "hibp", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n[{\"Name\":\"Adobe\",\"DataClasses\":[\"Passwords\"],\"Description\":\"hint secret-value\"}]\n")
	if res.Status != checker.StatusFound || res.Detail != "Adobe" {
		t.Fatalf("%+v", res)
	}
	if strings.Contains(res.Detail, "secret-value") || strings.Contains(res.Detail, "Passwords") {
		t.Fatalf("breach model leaked into detail %q", res.Detail)
	}
	if res.Evidence != "Breach list named Adobe." || strings.Contains(res.Evidence, "Passwords") || strings.Contains(res.Evidence, "secret-value") {
		t.Fatalf("evidence %q", res.Evidence)
	}
}

func TestLeakCheckOmitsSecrets(t *testing.T) {
	res := checkRaw(t, "leakcheck", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"success\":true,\"fields\":[\"password\"],\"password\":\"secret-value\",\"sources\":[{\"name\":\"Adobe\",\"date\":\"2013-10\"}]}\n")
	if res.Status != checker.StatusFound || res.Detail != "Adobe" {
		t.Fatalf("%+v", res)
	}
	if strings.Contains(res.Detail, "secret-value") || strings.Contains(res.Detail, "password") {
		t.Fatalf("secret leaked into detail %q", res.Detail)
	}
	if res.Evidence != "Breach list named Adobe." || strings.Contains(strings.ToLower(res.Evidence), "password") || strings.Contains(res.Evidence, "secret-value") {
		t.Fatalf("evidence %q", res.Evidence)
	}
}

func TestLeakCheckUnknownErrorIsNotAMiss(t *testing.T) {
	res := checkRaw(t, "leakcheck", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"success\":false,\"error\":\"Could not determine search type automatically\"}\n")
	if res.Status != checker.StatusError {
		t.Fatalf("%+v", res)
	}
}

func TestXposedOrNotOmitsSecrets(t *testing.T) {
	res := checkRaw(t, "xposedornot", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"breaches\":[[\"Adobe\",\"LinkedIn\"]],\"password\":\"secret-value\",\"hash\":\"abc\"}\n")
	if res.Status != checker.StatusFound {
		t.Fatalf("status %s", res.Status)
	}
	if res.Detail != "Adobe, LinkedIn" {
		t.Fatalf("detail %q", res.Detail)
	}
	if strings.Contains(res.Detail, "secret-value") || strings.Contains(res.Detail, "abc") {
		t.Fatalf("secret leaked into detail %q", res.Detail)
	}
	if res.Evidence != "Breach list named Adobe and LinkedIn." || strings.Contains(res.Evidence, "secret-value") || strings.Contains(res.Evidence, "abc") {
		t.Fatalf("evidence %q", res.Evidence)
	}
}

func TestGithubRejectsHTMLError(t *testing.T) {
	raw := "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><input type=\"hidden\" name=\"authenticity_token\" value=\"tok\"></body></html>\n---\nHTTP/1.1 422 Unprocessable Entity\nContent-Type: text/html\n\n<!DOCTYPE html><html><title>Oh no</title></html>\n"
	testRaw(t, "github", raw, checker.StatusError)
}

func TestChessInvalidEmail(t *testing.T) {
	raw := "HTTP/1.1 417 Expectation Failed\nContent-Type: application/json\n\n{\"isEmailAvailable\":false,\"reason\":\"Invalid Email\"}\n"
	testRaw(t, "chess", raw, checker.StatusError)
}

func TestDropboxMissingCSRF(t *testing.T) {
	raw := "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html></html>\n"
	testRaw(t, "dropbox", raw, checker.StatusError)
}

func TestDropboxRecoveryEmail(t *testing.T) {
	raw := "HTTP/1.1 200 OK\nSet-Cookie: __Host-js_csrf=csrf-token; Path=/\n\nok\n---\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"exists\":false,\"exists_as_recovery_email\":true}\n"
	testRaw(t, "dropbox", raw, checker.StatusFound)
}

func TestDiscordUnexpectedSuccess(t *testing.T) {
	raw := "HTTP/1.1 201 Created\nContent-Type: application/json\n\n{\"token\":\"nope\"}\n"
	testRaw(t, "discord", raw, checker.StatusError)
}

func testSite(t *testing.T, name string) {
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
			body, err := os.ReadFile(filepath.Join("..", "..", "testdata", name, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			res := checkRaw(t, name, string(body))
			if res.Status != tc.want {
				t.Fatalf("status %s detail %q", res.Status, res.Detail)
			}
			if tc.want == checker.StatusFound && res.Method != "breach" && res.DeleteURL == "" && res.SecurityURL == "" {
				t.Fatal("found result missing delete and security urls")
			}
			if tc.want != checker.StatusFound && (res.DeleteURL != "" || res.SecurityURL != "") {
				t.Fatalf("non-hit included links: %+v", res)
			}
			if res.Site != name || res.Domain == "" || res.Method == "" {
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

func testRaw(t *testing.T, name, raw string, want checker.Status) {
	t.Helper()
	res := checkRaw(t, name, raw)
	if res.Status != want {
		t.Fatalf("status %s detail %q", res.Status, res.Detail)
	}
}

func checkRaw(t *testing.T, name, raw string) checker.Result {
	t.Helper()
	client := clientFor(t, splitFixture(raw)...)
	return byName(t, name).Check(context.Background(), client, "nobody@example.com")
}

func byName(t *testing.T, name string) checker.Site {
	t.Helper()
	for _, site := range All() {
		if site.Name() == name {
			return site
		}
	}
	t.Fatalf("site %s is not registered", name)
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

func TestLeakCheckCapturesDates(t *testing.T) {
	res := checkRaw(t, "leakcheck", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"success\":true,\"sources\":[{\"name\":\"LinkedIn\",\"date\":\"2012-05\"},{\"name\":\"Adobe\",\"date\":\"2013-10\"}]}\n")
	if res.Status != checker.StatusFound {
		t.Fatalf("status %s", res.Status)
	}
	if len(res.Breaches) != 2 {
		t.Fatalf("breaches: %+v", res.Breaches)
	}
	got := map[string]string{}
	for _, h := range res.Breaches {
		got[h.Name] = h.Date
		if strings.Contains(strings.ToLower(h.Name), "password") || strings.Contains(h.Date, "secret") {
			t.Fatalf("secret leaked into breach hit %+v", h)
		}
	}
	if got["LinkedIn"] != "2012-05" || got["Adobe"] != "2013-10" {
		t.Fatalf("dates not captured: %+v", got)
	}
}
