package sites

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&github{}) }

// github reads the signup form's email check. A block page or an HTML
// error is never treated as "available".
type github struct{}

func (github) Name() string     { return "github" }
func (github) Domain() string   { return "github.com" }
func (github) Category() string { return "dev" }
func (github) Method() string   { return "register" }

func (s *github) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *github) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "github",
		domain:        "github.com",
		category:      "dev",
		method:        "register",
		deleteURL:     "https://github.com/settings/admin",
		securityURL:   "https://github.com/settings/security",
		foundEvidence: "Signup endpoint said this email is already registered.",
		missEvidence:  "Signup endpoint said this email is available.",
	}.result(status, detail, elapsed)
}

func (s *github) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	header := make(http.Header)
	header.Set("Accept", "text/html")
	status, _, body, err := get(ctx, c, "https://github.com/signup", header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	token := authenticityToken(body)
	if token == "" {
		return checker.StatusError, "signup page did not include a token"
	}
	form := url.Values{}
	form.Set("value", email)
	form.Set("authenticity_token", token)
	postHeader := make(http.Header)
	postHeader.Set("Accept", "*/*")
	postHeader.Set("Referer", "https://github.com/signup")
	status, _, body, err = postForm(ctx, c, "https://github.com/signup_check/email", form, postHeader)
	if err != nil {
		return fromErr(err)
	}
	return interpretGitHub(status, body)
}

func authenticityToken(body []byte) string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	token, _ := doc.Find(`input[name="authenticity_token"]`).Attr("value")
	return strings.TrimSpace(token)
}

func interpretGitHub(status int, body []byte) (checker.Status, string) {
	if limited(status, body) {
		return finishLimited()
	}
	if htmlPage(body) {
		return unexpected()
	}
	text := strings.ToLower(string(body))
	if strings.Contains(text, "already") || strings.Contains(text, "taken") || strings.Contains(text, "not available") {
		return checker.StatusFound, ""
	}
	if status == http.StatusOK {
		return checker.StatusNotFound, ""
	}
	return unexpected()
}

func htmlPage(body []byte) bool {
	text := strings.TrimSpace(strings.ToLower(string(body)))
	return strings.HasPrefix(text, "<!doctype html") || strings.HasPrefix(text, "<html") || strings.HasPrefix(text, "<head")
}
