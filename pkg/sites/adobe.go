package sites

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&adobe{}) }

// adobe asks the public sign-in account lookup whether the address is
// registered. An empty list means it is not. The request does not send mail.
type adobe struct{}

func (adobe) Name() string     { return "adobe" }
func (adobe) Domain() string   { return "adobe.com" }
func (adobe) Category() string { return "productivity" }
func (adobe) Method() string   { return "login" }

func (s *adobe) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *adobe) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "adobe",
		domain:        "adobe.com",
		category:      "productivity",
		method:        "login",
		deleteURL:     "https://account.adobe.com/privacy",
		securityURL:   "https://account.adobe.com/security",
		foundEvidence: "Sign-in lookup said this email is already registered.",
		missEvidence:  "Sign-in lookup returned no account for this email.",
	}.result(status, detail, elapsed)
}

func (s *adobe) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	payload, err := json.Marshal(map[string]string{
		"username":     email,
		"usernameType": "EMAIL",
	})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("X-IMS-CLIENTID", "adobedotcom2")
	status, _, body, err := postJSON(ctx, c, "https://auth.services.adobe.com/signin/v2/users/accounts", payload, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	trimmed := bytes.TrimSpace(body)
	if status != http.StatusOK || len(trimmed) == 0 || trimmed[0] != '[' {
		return unexpected()
	}
	var accounts []json.RawMessage
	if err := json.Unmarshal(trimmed, &accounts); err != nil {
		return unexpected()
	}
	if len(accounts) == 0 {
		return checker.StatusNotFound, ""
	}
	return checker.StatusFound, ""
}
