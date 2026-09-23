package profiles

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&devto{}) }

// devto reads the public user lookup. A 404 "not found" is a miss. The
// name field is the public display name. Other social handles in that
// payload are not copied.
type devto struct{}

func (devto) Name() string     { return "devto" }
func (devto) Domain() string   { return "dev.to" }
func (devto) Category() string { return "dev" }
func (devto) Method() string   { return "profile" }

func (s *devto) Check(ctx context.Context, c *http.Client, username string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, username)
	return profileResult("devto", "dev.to", "dev", profileURL("https://dev.to/", username), status, detail, time.Since(start))
}

func (s *devto) lookup(ctx context.Context, c *http.Client, username string) (checker.Status, string) {
	endpoint := "https://dev.to/api/users/by_username?url=" + url.QueryEscape(username)
	status, _, body, err := get(ctx, c, endpoint)
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
		Username string `json:"username"`
		Name     string `json:"name"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Username == "" {
		return unexpected()
	}
	return checker.StatusFound, resp.Name
}
