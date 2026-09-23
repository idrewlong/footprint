package sites

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&twitch{}) }

// twitch posts only the email to the signup endpoint. The response carries
// has_existing_account and does not include a password, so it cannot
// create an account. A body without that field is an error.
type twitch struct{}

func (twitch) Name() string     { return "twitch" }
func (twitch) Domain() string   { return "twitch.tv" }
func (twitch) Category() string { return "entertainment" }
func (twitch) Method() string   { return "register" }

func (s *twitch) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *twitch) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:        "twitch",
		domain:      "twitch.tv",
		category:    "entertainment",
		method:      "register",
		deleteURL:   "https://www.twitch.tv/settings/profile",
		securityURL: "https://www.twitch.tv/settings/security",
	}.result(status, detail, elapsed)
}

func (s *twitch) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	payload, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := postJSON(ctx, c, "https://passport.twitch.tv/protected_register", payload, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if bytes.Contains(bytes.ToLower(body), []byte("access_token")) {
		return checker.StatusError, "unexpected account response"
	}
	var resp struct {
		HasExisting *bool `json:"has_existing_account"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.HasExisting == nil {
		return unexpected()
	}
	if *resp.HasExisting {
		return checker.StatusFound, ""
	}
	return checker.StatusNotFound, ""
}
