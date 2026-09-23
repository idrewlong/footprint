package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&dropbox{}) }

// dropbox reads the signup page for its logged-out CSRF cookie, then asks
// the account RPC whether that email is already registered. The RPC is a
// read. It does not send mail.
type dropbox struct{}

func (dropbox) Name() string     { return "dropbox" }
func (dropbox) Domain() string   { return "dropbox.com" }
func (dropbox) Category() string { return "productivity" }
func (dropbox) Method() string   { return "register" }

func (s *dropbox) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *dropbox) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:        "dropbox",
		domain:      "dropbox.com",
		category:    "productivity",
		method:      "register",
		deleteURL:   "https://www.dropbox.com/account/delete",
		securityURL: "https://www.dropbox.com/account/security",
	}.result(status, detail, elapsed)
}

func (s *dropbox) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	status, header, body, err := get(ctx, c, "https://www.dropbox.com/register", nil)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status != http.StatusOK {
		return unexpected()
	}
	token := csrfCookie(header, "__Host-js_csrf")
	if token == "" {
		return unexpected()
	}
	payload, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	reqHeader := make(http.Header)
	reqHeader.Set("Accept", "application/json")
	reqHeader.Set("X-CSRF-Token", token)
	reqHeader.Set("Cookie", "__Host-js_csrf="+token)
	status, _, body, err = postJSON(ctx, c, "https://www.dropbox.com/2/account/check_user_with_email_exists", payload, reqHeader)
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
		Exists   *bool `json:"exists"`
		Recovery *bool `json:"exists_as_recovery_email"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Exists == nil {
		return unexpected()
	}
	if *resp.Exists || (resp.Recovery != nil && *resp.Recovery) {
		return checker.StatusFound, ""
	}
	return checker.StatusNotFound, ""
}

func csrfCookie(header http.Header, name string) string {
	for _, line := range header.Values("Set-Cookie") {
		pair, _, _ := strings.Cut(line, ";")
		key, value, ok := strings.Cut(pair, "=")
		if ok && strings.TrimSpace(key) == name {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
