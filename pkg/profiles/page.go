package profiles

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

// page is a public profile URL. A missing name answers 404 or 410.
// A 200 is a hit only when the title is not a login wall or a
// not-found page. Anything else stays an error.
type page struct {
	name, domain, category, rawURL string
}

func (p page) Name() string     { return p.name }
func (p page) Domain() string   { return p.domain }
func (p page) Category() string { return p.category }
func (p page) Method() string   { return "profile" }

func (p page) Check(ctx context.Context, c *http.Client, username string) checker.Result {
	start := time.Now()
	target := strings.Replace(p.rawURL, "{account}", url.PathEscape(username), 1)
	status, detail := p.lookup(ctx, c, target)
	return profileResult(p.name, p.domain, p.category, target, status, detail, time.Since(start))
}

func (p page) lookup(ctx context.Context, c *http.Client, target string) (checker.Status, string) {
	status, _, body, err := getAccept(ctx, c, target, "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	title := pageTitle(body)
	if status == http.StatusNotFound || status == http.StatusGone {
		return checker.StatusNotFound, ""
	}
	if status != http.StatusOK {
		return unexpected()
	}
	if m, ok := pageMarkers[p.name]; ok {
		if status, decided := m.decide(body); decided {
			if status == checker.StatusError {
				return unexpected()
			}
			return status, ""
		}
	}
	if wallTitle(title) {
		return unexpected()
	}
	if missingTitle(title) || missingMarkup(body) {
		return checker.StatusNotFound, ""
	}
	return checker.StatusFound, ""
}

// markers is page text that settles a 200 response for one site. A
// missing marker is a miss. An exists marker is a hit. When a site lists
// exists markers, a 200 with neither is an error, not a hit. A site with
// only missing markers falls back to the generic title checks.
// Take markers from the site's own pages, for a real and a missing name.
type markers struct {
	exists, missing []string
}

// pageMarkers are keyed by catalog page name.
var pageMarkers = map[string]markers{
	"insanejournal": {
		exists:  []string{"<b>User:</b>"},
		missing: []string{"<h2>Unknown user</h2>"},
	},
}

func (m markers) decide(body []byte) (checker.Status, bool) {
	text := strings.ToLower(string(body))
	for _, marker := range m.missing {
		if strings.Contains(text, strings.ToLower(marker)) {
			return checker.StatusNotFound, true
		}
	}
	for _, marker := range m.exists {
		if strings.Contains(text, strings.ToLower(marker)) {
			return checker.StatusFound, true
		}
	}
	if len(m.exists) > 0 {
		return checker.StatusError, true
	}
	return "", false
}

func pageTitle(body []byte) string {
	text := string(body)
	if len(text) > 32768 {
		text = text[:32768]
	}
	lower := strings.ToLower(text)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	open := strings.Index(text[start:], ">")
	if open < 0 {
		return ""
	}
	rest := text[start+open+1:]
	end := strings.Index(strings.ToLower(rest), "</title>")
	if end < 0 {
		return ""
	}
	return strings.Join(strings.Fields(rest[:end]), " ")
}

func wallTitle(title string) bool {
	text := strings.ToLower(title)
	walls := []string{
		"sign up",
		"signup",
		"log in",
		"login",
		"create account",
		"just a moment",
		"attention required",
		"access denied",
		"captcha",
	}
	for _, wall := range walls {
		if strings.Contains(text, wall) {
			return true
		}
	}
	return false
}

// missingMarkup catches a 200 page that still says the name is unregistered.
// The phrase has to be the page heading or a registration sentence, so a
// biography that mentions those words is left alone.
func missingMarkup(body []byte) bool {
	text := strings.ToLower(string(body))
	if len(text) > 65536 {
		text = text[:65536]
	}
	if strings.Contains(text, "not currently registered") || strings.Contains(text, "is not registered") {
		return true
	}
	phrases := []string{"unknown user", "user not found", "no such user", "user does not exist"}
	for _, tag := range []string{"<h1", "<h2", "<h3"} {
		rest := text
		for {
			start := strings.Index(rest, tag)
			if start < 0 {
				break
			}
			rest = rest[start:]
			open := strings.Index(rest, ">")
			if open < 0 {
				break
			}
			rest = rest[open+1:]
			end := strings.Index(rest, "</h")
			if end < 0 {
				break
			}
			heading := strings.Join(strings.Fields(stripTags(rest[:end])), " ")
			for _, phrase := range phrases {
				if strings.Contains(heading, phrase) {
					return true
				}
			}
			rest = rest[end:]
		}
	}
	return false
}

func missingTitle(title string) bool {
	text := strings.ToLower(title)
	phrases := []string{
		"not found",
		"does not exist",
		"doesn't exist",
		"page not found",
	}
	for _, phrase := range phrases {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}
