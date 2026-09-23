package profiles

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&docker{}) }

// docker reads the public Hub user record. A 404 "User not found" is a
// miss. A 200 with a username is a user, and a redirect to /v2/orgs/ is
// an organization with that name. Location, company, and gravatar email
// in the payload are not copied.
type docker struct{}

func (docker) Name() string     { return "docker" }
func (docker) Domain() string   { return "hub.docker.com" }
func (docker) Category() string { return "dev" }
func (docker) Method() string   { return "profile" }

func (s *docker) Check(ctx context.Context, c *http.Client, username string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, username)
	return profileResult("docker", "hub.docker.com", "dev", profileURL("https://hub.docker.com/u/", username), status, detail, time.Since(start))
}

func (s *docker) lookup(ctx context.Context, c *http.Client, username string) (checker.Status, string) {
	status, header, body, err := get(ctx, c, profileURL("https://hub.docker.com/v2/users/", username))
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status == http.StatusNotFound && strings.Contains(strings.ToLower(string(body)), "not found") {
		return checker.StatusNotFound, ""
	}
	if status == http.StatusPermanentRedirect && strings.Contains(header.Get("Location"), "/v2/orgs/") {
		return checker.StatusFound, ""
	}
	if status != http.StatusOK {
		return unexpected()
	}
	var resp struct {
		Username string `json:"username"`
		FullName string `json:"full_name"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Username == "" {
		return unexpected()
	}
	return checker.StatusFound, resp.FullName
}
