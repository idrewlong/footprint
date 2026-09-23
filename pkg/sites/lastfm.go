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

func init() { Register(&lastfm{}) }

// lastfm posts the email to the signup form's partial validator.
// "Looking good" with valid=true is a miss. A message that the address
// is already registered is a hit. Other validator failures stay errors.
type lastfm struct{}

func (lastfm) Name() string     { return "lastfm" }
func (lastfm) Domain() string   { return "last.fm" }
func (lastfm) Category() string { return "entertainment" }
func (lastfm) Method() string   { return "register" }

func (s *lastfm) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *lastfm) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:        "lastfm",
		domain:      "last.fm",
		category:    "entertainment",
		method:      "register",
		deleteURL:   "https://www.last.fm/settings/account",
		securityURL: "https://www.last.fm/settings/privacy",
	}.result(status, detail, elapsed)
}

func (s *lastfm) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	form := url.Values{}
	form.Set("email", email)
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("X-Requested-With", "XMLHttpRequest")
	status, _, body, err := postForm(ctx, c, "https://www.last.fm/join/partial/validate", form, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status != http.StatusOK {
		return unexpected()
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return unexpected()
	}
	raw, ok := envelope["email"]
	if !ok {
		return unexpected()
	}
	var emailResult struct {
		Valid    *bool    `json:"valid"`
		Messages []string `json:"error_messages"`
	}
	if err := json.Unmarshal(raw, &emailResult); err != nil || emailResult.Valid == nil {
		return unexpected()
	}
	if *emailResult.Valid {
		return checker.StatusNotFound, ""
	}
	joined := strings.ToLower(strings.Join(emailResult.Messages, " "))
	if strings.Contains(joined, "already") || strings.Contains(joined, "registered") {
		return checker.StatusFound, ""
	}
	return unexpected()
}
