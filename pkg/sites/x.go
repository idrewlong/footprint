package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&x{}) }

// x reads the public email-availability endpoint. taken is the only
// existence signal. A body without that field is an error.
type x struct{}

func (x) Name() string     { return "x" }
func (x) Domain() string   { return "x.com" }
func (x) Category() string { return "social" }
func (x) Method() string   { return "register" }

func (s *x) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *x) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "x",
		domain:        "x.com",
		category:      "social",
		method:        "register",
		deleteURL:     "https://x.com/settings/deactivate",
		securityURL:   "https://x.com/settings/account",
		foundEvidence: "Email availability endpoint said this email is taken.",
		missEvidence:  "Email availability endpoint said this email is not taken.",
	}.result(status, detail, elapsed)
}

func (s *x) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	endpoint := "https://api.twitter.com/i/users/email_available.json?email=" + url.QueryEscape(email)
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := get(ctx, c, endpoint, header)
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
		Valid *bool `json:"valid"`
		Taken *bool `json:"taken"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Taken == nil {
		return unexpected()
	}
	if *resp.Taken {
		return checker.StatusFound, ""
	}
	if resp.Valid != nil && *resp.Valid {
		return checker.StatusNotFound, ""
	}
	return unexpected()
}
