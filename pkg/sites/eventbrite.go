package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&eventbrite{}) }

// eventbrite reads the public sign-in lookup. exists false is a miss;
// exists true is a hit. The request does not send mail.
type eventbrite struct{}

func (eventbrite) Name() string     { return "eventbrite" }
func (eventbrite) Domain() string   { return "eventbrite.com" }
func (eventbrite) Category() string { return "social" }
func (eventbrite) Method() string   { return "login" }

func (s *eventbrite) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *eventbrite) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "eventbrite",
		domain:        "eventbrite.com",
		category:      "social",
		method:        "login",
		deleteURL:     "https://www.eventbrite.com/account-settings/close-account/",
		securityURL:   "https://www.eventbrite.com/account-settings/",
		foundEvidence: "Sign-in lookup said this email is already registered.",
		missEvidence:  "Sign-in lookup said this email is not registered.",
	}.result(status, detail, elapsed)
}

func (s *eventbrite) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	status, header, body, err := get(ctx, c, "https://www.eventbrite.com/signin/", nil)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status != http.StatusOK {
		return unexpected()
	}
	token := csrfCookie(header, "csrftoken")
	if token == "" {
		return unexpected()
	}
	payload, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	reqHeader := make(http.Header)
	reqHeader.Set("Accept", "application/json")
	reqHeader.Set("Content-Type", "application/json")
	reqHeader.Set("X-CSRFToken", token)
	reqHeader.Set("Referer", "https://www.eventbrite.com/signin/")
	reqHeader.Set("Cookie", "csrftoken="+token)
	status, _, body, err = postJSON(ctx, c, "https://www.eventbrite.com/api/v3/users/lookup/", payload, reqHeader)
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
		Exists *bool `json:"exists"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Exists == nil {
		return unexpected()
	}
	if *resp.Exists {
		return checker.StatusFound, ""
	}
	// Guard against HTML or alternate shapes that still parse as false.
	if !strings.Contains(string(body), `"exists"`) {
		return unexpected()
	}
	return checker.StatusNotFound, ""
}
