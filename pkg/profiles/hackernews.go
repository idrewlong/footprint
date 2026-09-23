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

func init() { Register(&hackernews{}) }

// hackernews reads the public user item. The API returns the JSON null
// for a missing id, which is a miss, not an error. The about text is the
// public bio. Karma and submission ids are not copied.
type hackernews struct{}

func (hackernews) Name() string     { return "hackernews" }
func (hackernews) Domain() string   { return "news.ycombinator.com" }
func (hackernews) Category() string { return "dev" }
func (hackernews) Method() string   { return "profile" }

func (s *hackernews) Check(ctx context.Context, c *http.Client, username string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, username)
	return profileResult("hackernews", "news.ycombinator.com", "dev", "https://news.ycombinator.com/user?id="+url.QueryEscape(username), status, detail, time.Since(start))
}

func (s *hackernews) lookup(ctx context.Context, c *http.Client, username string) (checker.Status, string) {
	status, _, body, err := get(ctx, c, "https://hacker-news.firebaseio.com/v0/user/"+username+".json")
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status != http.StatusOK {
		return unexpected()
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "null" {
		return checker.StatusNotFound, ""
	}
	var resp struct {
		ID    string `json:"id"`
		About string `json:"about"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.ID == "" {
		return unexpected()
	}
	return checker.StatusFound, resp.About
}
