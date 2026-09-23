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

func init() { Register(&spotify{}) }

// spotify calls the public signup validator. status 20, or an email error
// that says the address is already registered, is a hit. status 1 with no
// email error is a miss. The key is the public web signup client id.
type spotify struct{}

func (spotify) Name() string     { return "spotify" }
func (spotify) Domain() string   { return "spotify.com" }
func (spotify) Category() string { return "entertainment" }
func (spotify) Method() string   { return "register" }

func (s *spotify) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *spotify) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:        "spotify",
		domain:      "spotify.com",
		category:    "entertainment",
		method:      "register",
		deleteURL:   "https://www.spotify.com/account/privacy/",
		securityURL: "https://www.spotify.com/account/profile/",
	}.result(status, detail, elapsed)
}

func (s *spotify) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	query := url.Values{}
	query.Set("email", email)
	query.Set("validate", "1")
	query.Set("key", "bff58e9698f40080ec4f9ad97a2f21e0")
	endpoint := "https://spclient.wg.spotify.com/signup/public/v1/account?" + query.Encode()
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
		Status int `json:"status"`
		Errors struct {
			Email string `json:"email"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || !bytesContainsStatus(body) {
		return unexpected()
	}
	if resp.Status == 20 || strings.Contains(strings.ToLower(resp.Errors.Email), "already") {
		return checker.StatusFound, ""
	}
	if resp.Status == 1 && resp.Errors.Email == "" {
		return checker.StatusNotFound, ""
	}
	return unexpected()
}

func bytesContainsStatus(body []byte) bool {
	return strings.Contains(string(body), `"status"`)
}
