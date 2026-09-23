package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&instagram{}) }

// instagram posts the email to the signup availability endpoint after
// reading the page's CSRF token. A block or a body without an explicit
// availability flag is not reported as a miss.
type instagram struct{}

func (instagram) Name() string     { return "instagram" }
func (instagram) Domain() string   { return "instagram.com" }
func (instagram) Category() string { return "social" }
func (instagram) Method() string   { return "register" }

func (s *instagram) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *instagram) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "instagram",
		domain:        "instagram.com",
		category:      "social",
		method:        "register",
		deleteURL:     "https://www.instagram.com/accounts/remove/request/permanent/",
		securityURL:   "https://accountscenter.instagram.com/password_and_security",
		foundEvidence: "Signup endpoint said this email is already registered.",
		missEvidence:  "Signup endpoint said this email is available.",
	}.result(status, detail, elapsed)
}

var csrfTokenPattern = regexp.MustCompile(`"csrf_token":"([^"]+)"`)

func (s *instagram) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	header := make(http.Header)
	header.Set("Accept", "text/html")
	status, respHeader, body, err := get(ctx, c, "https://www.instagram.com/accounts/emailsignup/", header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	token := csrfToken(respHeader, body)
	if token == "" {
		return checker.StatusError, "signup page did not include a token"
	}
	form := url.Values{}
	form.Set("email", email)
	postHeader := make(http.Header)
	postHeader.Set("Accept", "application/json")
	postHeader.Set("X-CSRFToken", token)
	postHeader.Set("X-Requested-With", "XMLHttpRequest")
	postHeader.Set("X-IG-App-ID", "936619743392459")
	postHeader.Set("Referer", "https://www.instagram.com/accounts/emailsignup/")
	status, _, body, err = postForm(ctx, c, "https://www.instagram.com/api/v1/web/accounts/check_email/", form, postHeader)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	var resp struct {
		Available *bool  `json:"available"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return unexpected()
	}
	message := strings.ToLower(resp.Error)
	if strings.Contains(message, "taken") || strings.Contains(message, "already") {
		return checker.StatusFound, ""
	}
	if resp.Available != nil && *resp.Available && resp.Error == "" {
		return checker.StatusNotFound, ""
	}
	return unexpected()
}

func csrfToken(header http.Header, body []byte) string {
	for _, raw := range header.Values("Set-Cookie") {
		for _, part := range strings.Split(raw, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && name == "csrftoken" && value != "" {
				return value
			}
		}
	}
	if match := csrfTokenPattern.FindSubmatch(body); len(match) == 2 {
		return string(match[1])
	}
	return ""
}
