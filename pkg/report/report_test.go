package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func sample() []checker.Result {
	return []checker.Result{
		{Site: "spotify", Domain: "spotify.com", Category: "entertainment", Method: "register", Status: checker.StatusNotFound, Duration: 800 * time.Millisecond},
		{Site: "adobe", Domain: "adobe.com", Category: "productivity", Method: "login", Status: checker.StatusFound, DeleteURL: "https://account.adobe.com/privacy", SecurityURL: "https://account.adobe.com/security", Duration: 1200 * time.Millisecond},
		{Site: "github", Domain: "github.com", Category: "dev", Method: "register", Status: checker.StatusRateLimited, Detail: "rate limited", Duration: 300 * time.Millisecond},
		{Site: "slack", Domain: "slack.com", Category: "productivity", Method: "register", Status: checker.StatusError, Detail: "request failed", Duration: 50 * time.Millisecond},
	}
}

func TestBuildKeepsSummaryWhenFiltering(t *testing.T) {
	doc := Build("me@example.com", sample(), true)
	if doc.Summary.Found != 1 || doc.Summary.NotFound != 1 || doc.Summary.RateLimited != 1 || doc.Summary.Error != 1 {
		t.Fatalf("summary %+v", doc.Summary)
	}
	if len(doc.Results) != 1 || doc.Results[0].Site != "adobe" {
		t.Fatalf("results %+v", doc.Results)
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	doc := Build("me@example.com", sample(), false)
	if err := WriteJSON(&buf, doc); err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Email   string `json:"email"`
		Summary Summary
		Results []checker.Result `json:"results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Email != "me@example.com" || wire.Summary.Found != 1 {
		t.Fatalf("wire %+v", wire)
	}
	if !strings.Contains(buf.String(), `"duration_ms": 1200`) {
		t.Fatalf("duration not in milliseconds:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "https://account.adobe.com/privacy") {
		t.Fatal("delete url missing")
	}
}

func TestWriteHuman(t *testing.T) {
	results := append(sample(), checker.Result{
		Site: "zoom", Domain: "zoom.us", Category: "productivity", Method: "register", Status: checker.StatusFound,
		SecurityURL: "https://zoom.us/account", Duration: time.Second,
	}, checker.Result{
		Site: "xposedornot", Domain: "xposedornot.com", Category: "breach", Method: "breach", Status: checker.StatusFound,
		Detail: "Adobe, LinkedIn", Duration: time.Second,
	}, checker.Result{
		Site: "asciinema", Domain: "asciinema.org", Category: "dev", Method: "profile", Status: checker.StatusFound,
		ProfileURL: "https://asciinema.org/me", Detail: "Octo Cat", Duration: time.Second,
	})
	doc := Build("me@example.com", results, false)
	var buf bytes.Buffer
	if err := WriteHuman(&buf, doc, 2*time.Second, false); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	if strings.Contains(text, "\033[") {
		t.Fatal("color leaked")
	}
	if strings.Contains(text, "SITE") || strings.Contains(text, "login") || strings.Contains(text, "register") {
		t.Fatalf("human report included machine columns:\n%s", text)
	}
	if strings.Contains(text, "Adobe, LinkedIn") {
		t.Fatal("breach names stayed on one line")
	}
	if strings.Contains(text, "spotify") || strings.Contains(text, "https://account.adobe.com/security") {
		t.Fatalf("human report included a miss or the second link:\n%s", text)
	}
	found := strings.Index(text, "found ─")
	missed := strings.Index(text, "couldn't check ─")
	if found < 0 || missed < found {
		t.Fatalf("sections:\n%s", text)
	}
	for _, want := range []string{
		"me@example.com",
		"2.0s",
		"adobe",
		"productivity",
		"https://account.adobe.com/privacy",
		"https://zoom.us/account",
		"Adobe",
		"LinkedIn",
		"https://asciinema.org/me",
		"Octo Cat",
		"github",
		"rate limited",
		"slack",
		"error",
		"request failed",
		"4 found · 1 not found · 1 rate limited · 1 error",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
	adobe := strings.Index(text, "adobe")
	zoom := strings.Index(text, "zoom")
	if adobe < 0 || zoom < adobe || zoom > missed {
		t.Fatalf("found rows out of order:\n%s", text)
	}
	github := strings.Index(text, "github")
	slack := strings.Index(text, "slack")
	if github < missed || slack < github {
		t.Fatalf("couldn't-check rows out of order:\n%s", text)
	}
}

func TestWriteHumanColor(t *testing.T) {
	doc := Build("me@example.com", sample(), false)
	var buf bytes.Buffer
	if err := WriteHuman(&buf, doc, 2*time.Second, true); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	for _, want := range []string{
		"\033[1;32mfound\033[0m",
		"\033[1;32m●\033[0m",
		"\033[1madobe\033[0m",
		"\033[4;36mhttps://account.adobe.com/privacy\033[0m",
		"\033[1;33mcouldn't check\033[0m",
		"\033[1;33mrate limited\033[0m",
		"\033[1;31merror\033[0m",
		"\033[1;32m1 found\033[0m",
		"\033[2m1 not found\033[0m",
		"\033[1;33m1 rate limited\033[0m",
		"\033[1;31m1 error\033[0m",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
}

func TestWriteHumanEmpty(t *testing.T) {
	doc := Build("me@example.com", []checker.Result{
		{Site: "spotify", Status: checker.StatusNotFound},
	}, false)
	var buf bytes.Buffer
	if err := WriteHuman(&buf, doc, time.Second, false); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	if !strings.Contains(text, "No accounts found.") || !strings.Contains(text, "0 found · 1 not found · 0 rate limited · 0 error") {
		t.Fatalf("empty:\n%s", text)
	}
	if strings.Contains(text, "found ─") || strings.Contains(text, "spotify") || strings.Contains(text, "SITE") {
		t.Fatalf("empty report listed rows:\n%s", text)
	}

	user := BuildUser("octocat", nil, false)
	buf.Reset()
	if err := WriteHuman(&buf, user, time.Second, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No profiles found.") {
		t.Fatalf("user empty:\n%s", buf.String())
	}
}

func TestWriteMarkdown(t *testing.T) {
	doc := Build("me@example.com", sample(), false)
	var md bytes.Buffer
	if err := WriteMarkdown(&md, doc, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	out := md.String()
	if !strings.Contains(out, "https://account.adobe.com/security") {
		t.Fatal("markdown missing security link")
	}
	for _, section := range []string{"## Not found", "spotify", "## Rate limited", "github", "## Error", "slack"} {
		if !strings.Contains(out, section) {
			t.Fatalf("markdown missing %s:\n%s", section, out)
		}
	}
	if strings.Contains(out, "### spotify") {
		t.Fatal("markdown listed a miss as a found account")
	}
}
