package profiles

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&lichess{}) }

// lichess reads the public user API. A 404 "Not found" is a miss. A body
// with a username is a hit. Ratings and profile location are not copied.
type lichess struct{}

func (lichess) Name() string     { return "lichess" }
func (lichess) Domain() string   { return "lichess.org" }
func (lichess) Category() string { return "entertainment" }
func (lichess) Method() string   { return "profile" }

func (s *lichess) Check(ctx context.Context, c *http.Client, username string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, username)
	return profileResult("lichess", "lichess.org", "entertainment", profileURL("https://lichess.org/@/", username), status, detail, time.Since(start))
}

func (s *lichess) lookup(ctx context.Context, c *http.Client, username string) (checker.Status, string) {
	status, _, body, err := get(ctx, c, profileURL("https://lichess.org/api/user/", username))
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
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Username == "" {
		return unexpected()
	}
	return checker.StatusFound, ""
}
