package profiles

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&chess{}) }

// chess reads the public player API. A 404 that says the user was not
// found is a miss. The name field is the public display name. Location
// and streaming links in that payload are not copied.
type chess struct{}

func (chess) Name() string     { return "chess" }
func (chess) Domain() string   { return "chess.com" }
func (chess) Category() string { return "entertainment" }
func (chess) Method() string   { return "profile" }

func (s *chess) Check(ctx context.Context, c *http.Client, username string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, username)
	return profileResult("chess", "chess.com", "entertainment", profileURL("https://www.chess.com/member/", username), status, detail, time.Since(start))
}

func (s *chess) lookup(ctx context.Context, c *http.Client, username string) (checker.Status, string) {
	status, _, body, err := get(ctx, c, profileURL("https://api.chess.com/pub/player/", username))
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
