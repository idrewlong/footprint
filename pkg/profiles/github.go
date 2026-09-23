package profiles

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&github{}) }

// github reads the public users API. A 404 "Not Found" is a miss. A 200
// with a login is a hit. The HTML profile page is not used: asking for
// JSON makes GitHub answer with its retired content API (HTTP 410).
// Company, location, and email on the user record are not copied.
type github struct{}

func (github) Name() string     { return "github" }
func (github) Domain() string   { return "github.com" }
func (github) Category() string { return "dev" }
func (github) Method() string   { return "profile" }

func (s *github) Check(ctx context.Context, c *http.Client, username string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, username)
	return profileResult("github", "github.com", "dev", profileURL("https://github.com/", username), status, detail, time.Since(start))
}

func (s *github) lookup(ctx context.Context, c *http.Client, username string) (checker.Status, string) {
	status, _, body, err := get(ctx, c, profileURL("https://api.github.com/users/", username))
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status == http.StatusNotFound && strings.Contains(strings.ToLower(string(body)), "not found") {
		return checker.StatusNotFound, ""
	}
	if status != http.StatusOK {
		return unexpected()
	}
	var resp struct {
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Login == "" {
		return unexpected()
	}
	return checker.StatusFound, resp.Name
}
