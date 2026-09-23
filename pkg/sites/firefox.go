package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&firefox{}) }

// firefox calls the public account-status endpoint used by the login form.
// The body is only the email. Mozilla documents this as a status read,
// and it does not send mail.
type firefox struct{}

func (firefox) Name() string     { return "firefox" }
func (firefox) Domain() string   { return "firefox.com" }
func (firefox) Category() string { return "productivity" }
func (firefox) Method() string   { return "login" }

func (s *firefox) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *firefox) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:        "firefox",
		domain:      "firefox.com",
		category:    "productivity",
		method:      "login",
		deleteURL:   "https://accounts.firefox.com/settings/delete_account",
		securityURL: "https://accounts.firefox.com/settings",
	}.result(status, detail, elapsed)
}

func (s *firefox) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	payload, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	// Accept: application/json is rejected by this host. */* is the
	// value that returns the exists boolean.
	header := make(http.Header)
	header.Set("Accept", "*/*")
	status, _, body, err := postJSON(ctx, c, "https://api.accounts.firefox.com/v1/account/status", payload, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status != http.StatusOK {
		return unexpected()
	}
	var resp struct {
		Exists *bool `json:"exists"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Exists == nil {
		return unexpected()
	}
	if *resp.Exists {
		return checker.StatusFound, ""
	}
	return checker.StatusNotFound, ""
}
