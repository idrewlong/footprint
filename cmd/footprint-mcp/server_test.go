package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/idrewlong/footprint/pkg/casefile"
	"github.com/idrewlong/footprint/pkg/checker"
)

type fakeSite struct {
	name, category, method string
	status                 checker.Status
	calls                  *atomic.Int32
}

func (f fakeSite) Name() string     { return f.name }
func (f fakeSite) Domain() string   { return f.name + ".example" }
func (f fakeSite) Category() string { return f.category }
func (f fakeSite) Method() string   { return f.method }
func (f fakeSite) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	if f.calls != nil {
		f.calls.Add(1)
	}
	res := checker.Result{Status: f.status, Duration: time.Millisecond}
	if f.status == checker.StatusFound {
		res.Evidence = "Signup endpoint said this email is already registered."
		res.DeleteURL = "https://" + f.Domain() + "/delete"
	}
	return res
}

// catalogOf filters like sites.Select, including its unknown-name error.
func catalogOf(all ...checker.Site) catalogFunc {
	return func(categories, names []string) ([]checker.Site, error) {
		var out []checker.Site
		for _, n := range names {
			known := false
			for _, s := range all {
				known = known || s.Name() == n
			}
			if !known {
				return nil, fmt.Errorf("unknown site %q", n)
			}
		}
		for _, s := range all {
			if len(categories) > 0 && !contains(categories, s.Category()) {
				continue
			}
			if len(names) > 0 && !contains(names, s.Name()) {
				continue
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no sites matched")
		}
		return out, nil
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// resetCalls counts how often the password-reset site actually ran.
var resetCalls atomic.Int32

func mixedSites() []checker.Site {
	return []checker.Site{
		fakeSite{name: "alpha", category: "dev", method: "register", status: checker.StatusFound},
		fakeSite{name: "bravo", category: "social", method: "register", status: checker.StatusNotFound},
		fakeSite{name: "charlie", category: "social", method: "login", status: checker.StatusRateLimited},
		fakeSite{name: "delta", category: "shopping", method: checker.MethodPasswordReset, status: checker.StatusFound, calls: &resetCalls},
	}
}

func testConfig(sites ...checker.Site) config {
	return config{
		version:     "test",
		catalog:     catalogOf(sites...),
		transport:   http.DefaultTransport,
		concurrency: 4,
		timeout:     time.Second,
	}
}

// connect starts the server on an in-memory transport and returns a client
// session, as an MCP client would see it.
func connect(t *testing.T, cfg config) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverT, clientT := mcp.NewInMemoryTransports()
	ss, err := newServer(cfg).Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// call runs a tool and decodes its structured output into out. It returns
// the tool's error text when the call reports IsError.
func call(t *testing.T, cs *mcp.ClientSession, name string, args any, out any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if text, ok := c.(*mcp.TextContent); ok {
				msg.WriteString(text.Text)
			}
		}
		return msg.String()
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("%s output: %v\n%s", name, err, raw)
	}
	return ""
}

func TestToolsAreListed(t *testing.T) {
	cs := connect(t, testConfig(mixedSites()...))
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s is not marked read-only", tool.Name)
		}
	}
	if got := strings.Join(names, ","); got != "check_site,list_sites,scan_email" {
		t.Fatalf("tools = %s", got)
	}
}

func TestScanEmailReportsPartialRun(t *testing.T) {
	resetCalls.Store(0)
	cs := connect(t, testConfig(mixedSites()...))
	var out scanEmailOutput
	if msg := call(t, cs, "scan_email", map[string]any{"email": "me@example.com"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.Complete {
		t.Fatal("a run with a rate-limited and a skipped check was reported complete")
	}
	want := Summary{Found: 1, NotFound: 1, RateLimited: 1, Skipped: 1}
	if out.Summary != want {
		t.Fatalf("summary = %+v, want %+v", out.Summary, want)
	}
	if len(out.Results) != 3 || len(out.Skipped) != 1 || out.Skipped[0] != "delta" {
		t.Fatalf("results=%d skipped=%v", len(out.Results), out.Skipped)
	}
	if resetCalls.Load() != 0 {
		t.Fatal("a password-reset check ran without --allow-notify")
	}
	for _, phrase := range []string{"1 rate limited", "unknown, not absent", "--allow-notify"} {
		if !strings.Contains(out.Note, phrase) {
			t.Errorf("note missing %q: %s", phrase, out.Note)
		}
	}
	if out.Results[0].Site != "alpha" || out.Results[0].Confidence == "" {
		t.Fatalf("first result = %+v", out.Results[0])
	}
}

func TestScanEmailCompleteWithAllowNotify(t *testing.T) {
	resetCalls.Store(0)
	sites := mixedSites()
	cfg := testConfig(sites[0], sites[1], sites[3])
	cfg.allowNotify = true
	cs := connect(t, cfg)
	var out scanEmailOutput
	if msg := call(t, cs, "scan_email", map[string]any{"email": "me@example.com"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if !out.Complete || out.Summary.Found != 2 || resetCalls.Load() != 1 {
		t.Fatalf("complete=%v summary=%+v resetCalls=%d", out.Complete, out.Summary, resetCalls.Load())
	}
}

func TestScanEmailOnlyFoundKeepsFullSummary(t *testing.T) {
	cs := connect(t, testConfig(mixedSites()...))
	var out scanEmailOutput
	if msg := call(t, cs, "scan_email", map[string]any{"email": "me@example.com", "only_found": true}, &out); msg != "" {
		t.Fatal(msg)
	}
	if len(out.Results) != 1 || out.Results[0].Status != checker.StatusFound {
		t.Fatalf("results = %+v", out.Results)
	}
	if out.Summary.NotFound != 1 || out.Summary.RateLimited != 1 {
		t.Fatalf("summary dropped non-hits: %+v", out.Summary)
	}
}

func TestScanEmailCategoryFilter(t *testing.T) {
	cs := connect(t, testConfig(mixedSites()...))
	var out scanEmailOutput
	if msg := call(t, cs, "scan_email", map[string]any{"email": "me@example.com", "categories": []string{"dev"}}, &out); msg != "" {
		t.Fatal(msg)
	}
	if len(out.Results) != 1 || out.Results[0].Site != "alpha" || !out.Complete {
		t.Fatalf("out = %+v", out)
	}
}

func TestInvalidEmailIsToolError(t *testing.T) {
	cs := connect(t, testConfig(mixedSites()...))
	for tool, args := range map[string]map[string]any{
		"scan_email": {"email": "Me <me@example.com>"},
		"check_site": {"email": "Me <me@example.com>", "site": "alpha"},
	} {
		msg := call(t, cs, tool, args, &struct{}{})
		if !strings.Contains(msg, "not valid") {
			t.Errorf("%s: error = %q", tool, msg)
		}
	}
}

func TestCheckSite(t *testing.T) {
	resetCalls.Store(0)
	cs := connect(t, testConfig(mixedSites()...))
	var out checkSiteOutput
	if msg := call(t, cs, "check_site", map[string]any{"email": "me@example.com", "site": "charlie"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.Result.Site != "charlie" || out.Result.Status != checker.StatusRateLimited {
		t.Fatalf("result = %+v", out.Result)
	}
	if msg := call(t, cs, "check_site", map[string]any{"email": "me@example.com", "site": "delta"}, &out); !strings.Contains(msg, "--allow-notify") {
		t.Fatalf("notifying site ran or gave the wrong error: %q", msg)
	}
	if resetCalls.Load() != 0 {
		t.Fatal("a password-reset check ran without --allow-notify")
	}
	if msg := call(t, cs, "check_site", map[string]any{"email": "me@example.com", "site": "nope"}, &out); !strings.Contains(msg, "unknown site") {
		t.Fatalf("unknown site: %q", msg)
	}
}

func TestListSites(t *testing.T) {
	cs := connect(t, testConfig(mixedSites()...))
	var out listSitesOutput
	if msg := call(t, cs, "list_sites", map[string]any{}, &out); msg != "" {
		t.Fatal(msg)
	}
	if len(out.Sites) != 4 {
		t.Fatalf("sites = %+v", out.Sites)
	}
	for _, s := range out.Sites {
		if s.Name == "delta" && (s.Enabled || !s.Notifies) {
			t.Fatalf("delta = %+v, want notifies and disabled", s)
		}
	}
	if msg := call(t, cs, "list_sites", map[string]any{"category": "social"}, &out); msg != "" || len(out.Sites) != 2 {
		t.Fatalf("social: %q %+v", msg, out.Sites)
	}
}

func TestScanEmailSavesToVerifiedLedger(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "audit-ed25519.key")
	t.Setenv("FOOTPRINT_SIGN_KEY", keyPath)
	cfg := testConfig(mixedSites()...)
	cfg.save, cfg.caseDir, cfg.caseID, cfg.authority = true, t.TempDir(), "C-1", "warrant 1"
	cs := connect(t, cfg)
	var out scanEmailOutput
	if msg := call(t, cs, "scan_email", map[string]any{"email": "me@example.com"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.SavedTo == "" || out.AuditHead == "" {
		t.Fatalf("saved_to=%q audit_head=%q", out.SavedTo, out.AuditHead)
	}
	saved, err := casefile.Load(out.SavedTo)
	if err != nil || saved.CaseID != "C-1" || saved.Authority != "warrant 1" {
		t.Fatalf("saved case: %+v err=%v", saved, err)
	}
	pub, err := casefile.ReadPublicKey(casefile.PublicKeyPath(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := casefile.Verify(cfg.caseDir, casefile.VerifyOptions{Trusted: []ed25519.PublicKey{pub}, Head: out.AuditHead})
	if err != nil || !rep.OK() {
		t.Fatalf("verify: %+v err=%v", rep, err)
	}
}

func TestParseConfig(t *testing.T) {
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--save"}, 2, "--case-id and --authority"},
		{[]string{"--save", "--case-id", "C-1"}, 2, "--case-id and --authority"},
		{[]string{"--proxy", "ftp://nope"}, 2, "proxy"},
		{[]string{"--concurrency", "0"}, 2, "--concurrency"},
		{[]string{"extra"}, 2, "Usage"},
		{[]string{"--save", "--case-id", "C-1", "--authority", "w", "--case-dir", os.TempDir()}, 0, ""},
	}
	for _, tc := range cases {
		var stderr bytes.Buffer
		_, code := parseConfig(tc.args, &stderr)
		if code != tc.code || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("%v: code %d, stderr %q", tc.args, code, stderr.String())
		}
	}
}
