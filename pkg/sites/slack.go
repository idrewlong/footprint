package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&slack{}) }

// slack posts the email to the public signup check. A challenge response
// means Slack did not answer, so it is rate_limited rather than a miss.
type slack struct{}

func (slack) Name() string     { return "slack" }
func (slack) Domain() string   { return "slack.com" }
func (slack) Category() string { return "productivity" }
func (slack) Method() string   { return "register" }

func (s *slack) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *slack) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:        "slack",
		domain:      "slack.com",
		category:    "productivity",
		method:      "register",
		deleteURL:   "https://slack.com/account/settings",
		securityURL: "https://slack.com/account/settings",
	}.result(status, detail, elapsed)
}

func (s *slack) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	form := url.Values{}
	form.Set("email", email)
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := postForm(ctx, c, "https://slack.com/api/signup.checkEmail", form, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	var resp struct {
		OK        bool   `json:"ok"`
		Error     string `json:"error"`
		Challenge *bool  `json:"challenge_response"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return unexpected()
	}
	if resp.Challenge != nil && *resp.Challenge {
		return checker.StatusRateLimited, "challenge"
	}
	message := strings.ToLower(resp.Error)
	if strings.Contains(message, "rate") || strings.Contains(message, "limit") {
		return checker.StatusRateLimited, "rate limited"
	}
	if strings.Contains(message, "already") || strings.Contains(message, "in_use") || strings.Contains(message, "taken") {
		return checker.StatusFound, ""
	}
	if resp.OK && resp.Error == "" {
		return checker.StatusNotFound, ""
	}
	return unexpected()
}
