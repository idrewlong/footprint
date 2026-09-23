package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&microsoft{}) }

// microsoft reads GetCredentialType, the same lookup the login page uses
// before a password is entered. ThrottleStatus is honored first: a throttled
// response has reported IfExistsResult 0 for an address that does not exist.
type microsoft struct{}

func (microsoft) Name() string     { return "microsoft" }
func (microsoft) Domain() string   { return "microsoft.com" }
func (microsoft) Category() string { return "productivity" }
func (microsoft) Method() string   { return "login" }

func (s *microsoft) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *microsoft) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "microsoft",
		domain:        "microsoft.com",
		category:      "productivity",
		method:        "login",
		deleteURL:     "https://account.live.com/closeaccount.aspx",
		securityURL:   "https://account.microsoft.com/security",
		foundEvidence: "Login lookup said this email is already registered.",
		missEvidence:  "Login lookup said this email is not registered.",
	}.result(status, detail, elapsed)
}

func (s *microsoft) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	payload, err := json.Marshal(map[string]any{
		"username":                       email,
		"isOtherIdpSupported":            true,
		"isRemoteNGCSupported":           true,
		"isCookieBannerShown":            false,
		"isFidoSupported":                true,
		"checkPhones":                    false,
		"forceotclogin":                  false,
		"isExternalFederationDisallowed": false,
		"isRemoteConnectSupported":       false,
		"federationFlags":                0,
		"isSignup":                       false,
		"isAccessPassSupported":          true,
	})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := postJSON(ctx, c, "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US", payload, header)
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
		IfExistsResult *int `json:"IfExistsResult"`
		ThrottleStatus *int `json:"ThrottleStatus"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.IfExistsResult == nil {
		return unexpected()
	}
	if resp.ThrottleStatus != nil && *resp.ThrottleStatus != 0 {
		return checker.StatusRateLimited, "throttled"
	}
	switch *resp.IfExistsResult {
	case 0, 5, 6:
		return checker.StatusFound, ""
	case 1:
		return checker.StatusNotFound, ""
	case 2:
		return checker.StatusRateLimited, "throttled"
	default:
		return unexpected()
	}
}
