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
		{Site: "adobe", Domain: "adobe.com", Category: "productivity", Method: "login", Status: checker.StatusFound, Evidence: "Sign-in lookup said this email is already registered.", DeleteURL: "https://account.adobe.com/privacy", SecurityURL: "https://account.adobe.com/security", Duration: 1200 * time.Millisecond},
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
	if !strings.Contains(buf.String(), `"evidence": "Sign-in lookup said this email is already registered."`) {
		t.Fatal("evidence missing")
	}
}

func TestWriteHuman(t *testing.T) {
	results := append(sample(), checker.Result{
		Site: "zoom", Domain: "zoom.us", Category: "productivity", Method: "register", Status: checker.StatusFound,
		Evidence: "Signup endpoint said this email is already registered.", SecurityURL: "https://zoom.us/account", Duration: time.Second,
	}, checker.Result{
		Site: "xposedornot", Domain: "xposedornot.com", Category: "breach", Method: "breach", Status: checker.StatusFound,
		Evidence: "Breach list named Adobe and LinkedIn.", Detail: "Adobe, LinkedIn", Duration: time.Second,
	}, checker.Result{
		Site: "asciinema", Domain: "asciinema.org", Category: "dev", Method: "profile", Status: checker.StatusFound,
		Evidence: "Public profile exists for this username.", ProfileURL: "https://asciinema.org/me", Detail: "Octo Cat", Duration: time.Second,
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
	if strings.Contains(text, "SITE") || strings.Contains(text, "METHOD") {
		t.Fatalf("human report included a column header:\n%s", text)
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
		"login · Sign-in lookup said this email is already registered.",
		"register · Signup endpoint said this email is already registered.",
		"breach · Breach list named Adobe and LinkedIn.",
		"profile · Public profile exists for this username.",
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
		"\033[1mlogin\033[0m · \033[2mSign-in lookup said this email is already registered.\033[0m",
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
	results := []checker.Result{
		{Site: "spotify", Domain: "spotify.com", Category: "entertainment", Method: "register", Status: checker.StatusNotFound, Evidence: "Signup validator said this email is available."},
		{Site: "adobe", Domain: "adobe.com", Category: "productivity", Method: "login", Status: checker.StatusFound, Evidence: "Sign-in lookup said this email is already registered.", DeleteURL: "https://account.adobe.com/privacy", SecurityURL: "https://account.adobe.com/security"},
		{Site: "zoom", Domain: "zoom.us", Category: "productivity", Method: "register", Status: checker.StatusFound, Evidence: "Signup endpoint said this email is already registered.", DeleteURL: "https://zoom.us/account/delete", SecurityURL: "https://zoom.us/account"},
		{Site: "xposedornot", Domain: "xposedornot.com", Category: "security", Method: "breach", Status: checker.StatusFound, Evidence: "Breach list named Zoom and LinkedIn.", Detail: "Zoom, LinkedIn"},
		{Site: "github", Domain: "github.com", Category: "dev", Method: "profile", Status: checker.StatusFound, Evidence: "Public profile exists for this username.", ProfileURL: "https://github.com/me"},
		{Site: "slack", Domain: "slack.com", Category: "productivity", Method: "register", Status: checker.StatusRateLimited, Detail: "rate limited"},
		{Site: "discord", Domain: "discord.com", Category: "social", Method: "register", Status: checker.StatusError, Detail: "request failed"},
	}
	doc := Build("me@example.com", results, false)
	doc.Username = "me"
	var md bytes.Buffer
	meta := Meta{Version: "v0.1.0", RanAt: time.Date(2026, 9, 23, 18, 32, 0, 0, time.UTC), Elapsed: 2 * time.Second}
	if err := WriteMarkdown(&md, doc, meta); err != nil {
		t.Fatal(err)
	}
	out := md.String()
	for _, want := range []string{
		"**Bottom line:** 2 email matches and 1 breach for `me@example.com`, and 1 public profile for `me` (weaker than an email match; the username was taken from the mailbox). 2 checks were not completed.",
		"## Findings",
		"| Site | Method | Evidence |",
		"| adobe | login | Sign-in lookup said this email is already registered. |",
		"| zoom | register | Signup endpoint said this email is already registered. |",
		"| xposedornot | breach | Breach list named Zoom and LinkedIn. |",
		"| github | profile | Public profile exists for this username. Weaker than an email match: the username was taken from the mailbox. https://github.com/me |",
		"## Coverage",
		"4 found, 1 not found, 1 rate limited, 1 error.",
		"footprint v0.1.0 · 2026-09-23 18:32 UTC · 2.0s",
		"Unchecked:",
		"- **slack** — rate limited",
		"- **discord** — error. request failed",
		"## Actions",
		"- **zoom** — Change the password and turn on 2FA. This address appears in the Zoom breach.",
		"  - Security: https://zoom.us/account",
		"  - Delete: https://zoom.us/account/delete",
		"- **adobe**",
		"  - Security: https://account.adobe.com/security",
		"  - Delete: https://account.adobe.com/privacy",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "spotify") {
		t.Fatalf("markdown listed a miss:\n%s", out)
	}
	adobe := strings.Index(out, "| adobe |")
	zoom := strings.Index(out, "| zoom |")
	breach := strings.Index(out, "| xposedornot |")
	profile := strings.Index(out, "| github |")
	if adobe < 0 || zoom < adobe || breach < zoom || profile < breach {
		t.Fatalf("findings out of strength order:\n%s", out)
	}
	zoomAction := strings.Index(out, "- **zoom**")
	adobeAction := strings.Index(out, "- **adobe**")
	if zoomAction < 0 || adobeAction < zoomAction {
		t.Fatalf("breach match was not first:\n%s", out)
	}
	if strings.Contains(out[adobeAction:], "Change the password") {
		t.Fatalf("unrelated account got the breach note:\n%s", out)
	}
	if strings.Contains(out, "secret") || strings.Contains(out, "password:") {
		t.Fatalf("markdown included a stolen value:\n%s", out)
	}
}

func TestWriteMarkdownUsernameOnly(t *testing.T) {
	doc := BuildUser("octocat", []checker.Result{
		{Site: "github", Method: "profile", Status: checker.StatusFound, Evidence: "Public profile exists for this username.", ProfileURL: "https://github.com/octocat"},
	}, false)
	var md bytes.Buffer
	if err := WriteMarkdown(&md, doc, Meta{Version: "dev", Elapsed: time.Second}); err != nil {
		t.Fatal(err)
	}
	out := md.String()
	if !strings.Contains(out, "**Bottom line:** 1 public profile for `octocat`.") {
		t.Fatalf("bottom line:\n%s", out)
	}
	if !strings.Contains(out, "| github | profile | Public profile exists for this username. https://github.com/octocat |") {
		t.Fatalf("profile finding:\n%s", out)
	}
	if strings.Contains(out, "weaker than an email match") {
		t.Fatalf("explicit username was labeled as a mailbox guess:\n%s", out)
	}
	if !strings.Contains(out, "Unchecked:\n\nNone.") {
		t.Fatalf("unchecked:\n%s", out)
	}
}

func TestWriteMarkdownGroupsDomainAndInfrastructure(t *testing.T) {
	doc := Build("me@example.com", []checker.Result{
		{Site: "adobe", Method: "login", Status: checker.StatusFound, Evidence: "Sign-in lookup said this email is already registered."},
		{Site: "mx", Method: "dns", Status: checker.StatusFound, Evidence: "MX records point at mx.example.com."},
	}, false)
	doc.SubjectDomain = "example.com"
	var md bytes.Buffer
	if err := WriteMarkdown(&md, doc, Meta{Version: "dev", Elapsed: time.Second}); err != nil {
		t.Fatal(err)
	}
	out := md.String()
	findings := strings.Index(out, "## Findings")
	domain := strings.Index(out, "## Domain")
	if findings < 0 || domain < findings {
		t.Fatalf("sections:\n%s", out)
	}
	findingsBody := out[findings:domain]
	if !strings.Contains(findingsBody, "| adobe | login |") {
		t.Fatalf("adobe not under Findings:\n%s", out)
	}
	if strings.Contains(findingsBody, "| mx |") {
		t.Fatalf("mx stayed under Findings:\n%s", out)
	}
	if !strings.Contains(out[domain:], "| mx | dns | MX records point at mx.example.com. |") {
		t.Fatalf("mx not under Domain:\n%s", out)
	}
	if !strings.Contains(out, "**Bottom line:** 1 email match for `me@example.com`.") {
		t.Fatalf("bottom line counted MX as an email match:\n%s", out)
	}
	if strings.Contains(out, "2 email matches") {
		t.Fatalf("bottom line counted MX as an email match:\n%s", out)
	}

	ipDoc := Document{
		SubjectIP: "8.8.8.8",
		Summary:   Summarize([]checker.Result{{Site: "geoip", Method: "infra", Status: checker.StatusFound}}),
		Results: []checker.Result{
			{
				Site:     "geoip",
				Method:   "infra",
				Status:   checker.StatusFound,
				Evidence: "GeoIP database places this address in Ashburn, Virginia, US. This is the network's city, not a person or a street address.",
			},
		},
	}
	md.Reset()
	if err := WriteMarkdown(&md, ipDoc, Meta{Version: "dev", Elapsed: time.Second}); err != nil {
		t.Fatal(err)
	}
	ipOut := md.String()
	if !strings.Contains(ipOut, "## Infrastructure") {
		t.Fatalf("missing Infrastructure:\n%s", ipOut)
	}
	if !strings.Contains(ipOut, "not a person or a street address") {
		t.Fatalf("missing geoip evidence:\n%s", ipOut)
	}
	if strings.Contains(ipOut, "No email matches") {
		t.Fatalf("IP-only note described itself as email:\n%s", ipOut)
	}
}

func TestWriteHumanSubjectHeader(t *testing.T) {
	cases := []struct {
		name string
		doc  Document
		want string
	}{
		{name: "domain", doc: Document{SubjectDomain: "example.com"}, want: "example.com"},
		{name: "ip", doc: Document{SubjectIP: "8.8.8.8"}, want: "8.8.8.8"},
		{name: "entity", doc: Document{SubjectEntity: "Apple Inc."}, want: "Apple Inc."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteHuman(&buf, tc.doc, time.Second, false); err != nil {
				t.Fatal(err)
			}
			first := strings.SplitN(buf.String(), "\n", 2)[0]
			if !strings.HasPrefix(first, tc.want) {
				t.Fatalf("header %q, want prefix %q\nfull:\n%s", first, tc.want, buf.String())
			}
		})
	}
}

func TestWriteHumanSubjectEmptyMessage(t *testing.T) {
	doc := Document{
		SubjectIP: "8.8.8.8",
		Summary:   Summarize([]checker.Result{{Site: "ptr", Method: "infra", Status: checker.StatusNotFound}}),
		Results:   []checker.Result{{Site: "ptr", Method: "infra", Status: checker.StatusNotFound}},
	}
	var buf bytes.Buffer
	if err := WriteHuman(&buf, doc, time.Second, false); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	if !strings.Contains(text, "No network details found.") {
		t.Fatalf("missing subject empty message:\n%s", text)
	}
	if strings.Contains(text, "No accounts found.") {
		t.Fatalf("used account empty message:\n%s", text)
	}
}

func TestWriteMarkdownEntitySection(t *testing.T) {
	doc := Document{
		SubjectEntity: "Apple Inc.",
		Summary:       Summarize([]checker.Result{{Site: "ofac", Method: "entity", Status: checker.StatusFound}}),
		Results: []checker.Result{
			{
				Site:     "ofac",
				Method:   "entity",
				Status:   checker.StatusFound,
				Evidence: "Local OFAC SDN list matches this name as Apple Inc., program SDGT.",
			},
		},
	}
	var md bytes.Buffer
	if err := WriteMarkdown(&md, doc, Meta{Version: "dev", Elapsed: time.Second}); err != nil {
		t.Fatal(err)
	}
	out := md.String()
	if !strings.Contains(out, "## Entity") {
		t.Fatalf("missing Entity section:\n%s", out)
	}
	if !strings.Contains(out, "| ofac | entity |") {
		t.Fatalf("missing ofac row:\n%s", out)
	}
}
