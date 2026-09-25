package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func TestProbeUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"probe"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(stderr.String(), "footprint probe") {
		t.Fatalf("usage missing:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("usage wrote to stdout")
	}
}

func TestProbeRejectsInvalidEmail(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := execute([]string{"probe", "github", "not-an-email"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(stderr.String(), "email address is not valid") {
		t.Fatalf("stderr %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("invalid email wrote to stdout")
	}
}

func TestProbeUnknownSite(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := execute([]string{"probe", "not-a-site", "me@example.com"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown site") {
		t.Fatalf("stderr %s", stderr.String())
	}
}

func TestNotifyBlocked(t *testing.T) {
	site := fakeSite{name: "gitlab", domain: "gitlab.com", method: "password_reset"}
	msg := notifyBlocked(site, "me@example.com", false)
	if !strings.Contains(msg, "--allow-notify") || !strings.Contains(msg, "gitlab") {
		t.Fatalf("msg %q", msg)
	}
	if notifyBlocked(site, "me@example.com", true) != "" {
		t.Fatal("opt-in still blocked")
	}
	if notifyBlocked(fakeSite{name: "github", method: "register"}, "me@example.com", false) != "" {
		t.Fatal("register check was blocked")
	}
}

type httpSite struct {
	name, domain, method, rawURL string
}

func (s httpSite) Name() string     { return s.name }
func (s httpSite) Domain() string   { return s.domain }
func (s httpSite) Category() string { return "dev" }
func (s httpSite) Method() string   { return s.method }
func (s httpSite) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.rawURL, strings.NewReader("email="+email))
	if err != nil {
		return checker.Result{Status: checker.StatusError, Detail: err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return checker.Result{Status: checker.StatusError, Detail: err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return checker.Result{Status: checker.StatusError, Detail: err.Error()}
	}
	status := checker.StatusNotFound
	if resp.StatusCode == http.StatusTooManyRequests {
		status = checker.StatusRateLimited
	}
	return checker.Result{Status: status, Detail: string(body), Evidence: "probe test"}
}

func TestProbePrintsRawExchange(t *testing.T) {
	var seenUA, seenAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA = r.Header.Get("User-Agent")
		seenAccept = r.Header.Get("Accept")
		w.Header().Set("X-Signal", "available")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"exists":false}`))
	}))
	defer srv.Close()

	site := httpSite{name: "local", domain: "local.test", method: "register", rawURL: srv.URL}
	res, exchanges := probeSite(context.Background(), site, "me@example.com", nil, 5*time.Second)
	if res.Status != checker.StatusNotFound {
		t.Fatalf("status %s detail %s", res.Status, res.Detail)
	}
	if len(exchanges) != 1 {
		t.Fatalf("exchanges %d", len(exchanges))
	}
	ex := exchanges[0]
	if ex.method != http.MethodPost || ex.statusCode != http.StatusOK {
		t.Fatalf("exchange %s %d", ex.method, ex.statusCode)
	}
	if string(ex.body) != `{"exists":false}` {
		t.Fatalf("body %q", ex.body)
	}
	if ex.respHeader.Get("X-Signal") != "available" {
		t.Fatalf("headers %v", ex.respHeader)
	}
	if seenAccept != "application/json" {
		t.Fatalf("accept %q", seenAccept)
	}
	if seenUA == "" || ex.reqHeader.Get("User-Agent") == "" {
		t.Fatal("probe dropped the client user agent")
	}

	var stdout bytes.Buffer
	if err := writeProbe(&stdout, site, "me@example.com", res, exchanges); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{
		"site: local",
		"status: not_found",
		"evidence: probe test",
		"POST " + srv.URL,
		"< 200 OK",
		"< X-Signal: available",
		`{"exists":false}`,
		"> Accept: application/json",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
}

func TestProbeKeepsChallengeBody(t *testing.T) {
	const page = "<html><title>Just a moment...</title></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	site := httpSite{name: "local", domain: "local.test", method: "register", rawURL: srv.URL}
	res, exchanges := probeSite(context.Background(), site, "me@example.com", nil, 5*time.Second)
	if res.Status != checker.StatusRateLimited {
		t.Fatalf("check saw %s (%s), want rate_limited", res.Status, res.Detail)
	}
	if len(exchanges) != 1 {
		t.Fatalf("exchanges %d", len(exchanges))
	}
	if exchanges[0].statusCode != http.StatusForbidden {
		t.Fatalf("raw status %d", exchanges[0].statusCode)
	}
	if string(exchanges[0].body) != page {
		t.Fatalf("raw body %q", exchanges[0].body)
	}
}
