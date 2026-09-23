package sites

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&gravatar{}) }

// gravatar looks up the public profile for the email's hash.
// A 404 that says the user was not found is a miss. Anything else that
// is not a profile document is an error. The request does not send mail.
type gravatar struct{}

func (gravatar) Name() string     { return "gravatar" }
func (gravatar) Domain() string   { return "gravatar.com" }
func (gravatar) Category() string { return "social" }
func (gravatar) Method() string   { return "login" }

func (s *gravatar) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *gravatar) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "gravatar",
		domain:        "gravatar.com",
		category:      "social",
		method:        "login",
		deleteURL:     "https://gravatar.com/profile",
		securityURL:   "https://gravatar.com/profile",
		foundEvidence: "Profile lookup found an account for this email.",
		missEvidence:  "Profile lookup said this email has no account.",
	}.result(status, detail, elapsed)
}

func (s *gravatar) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	sum := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email))))
	endpoint := "https://en.gravatar.com/" + hex.EncodeToString(sum[:]) + ".json"
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := get(ctx, c, endpoint, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	text := strings.ToLower(string(body))
	if status == http.StatusNotFound && strings.Contains(text, "user not found") {
		return checker.StatusNotFound, ""
	}
	if status == http.StatusOK && strings.Contains(text, `"entry"`) {
		return checker.StatusFound, ""
	}
	return unexpected()
}
