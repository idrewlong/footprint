package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&apple{}) }

// apple loads the public create-account page for a session, then asks the
// Apple Account validator whether the email is already used. The lookup
// does not send mail. Apple answers 503 once an IP has made a few lookups,
// so a 503 is rate limited, not a miss. The widget key is the public web
// client key.
type apple struct{}

func (apple) Name() string     { return "apple" }
func (apple) Domain() string   { return "apple.com" }
func (apple) Category() string { return "productivity" }
func (apple) Method() string   { return "register" }

func (s *apple) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *apple) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "apple",
		domain:        "apple.com",
		category:      "productivity",
		method:        "register",
		deleteURL:     "https://privacy.apple.com/",
		securityURL:   "https://account.apple.com/account/manage/section/security",
		foundEvidence: "Create-account validator said this email is already used.",
		missEvidence:  "Create-account validator said this email is not used.",
	}.result(status, detail, elapsed)
}

func (s *apple) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	header := make(http.Header)
	header.Set("Accept", "text/html")
	status, pageHeader, body, err := get(ctx, c, "https://account.apple.com/account", header)
	if err != nil {
		return fromErr(err)
	}
	if appleLimited(status, body) {
		return finishLimited()
	}
	scnt := pageHeader.Get("Scnt")
	session := pageHeader.Get("X-Apple-ID-Session-Id")
	if status != http.StatusOK || scnt == "" || session == "" {
		return checker.StatusError, "account page did not include a session"
	}
	payload, err := json.Marshal(map[string]string{"emailAddress": email})
	if err != nil {
		return checker.StatusError, "request failed"
	}
	reqHeader := make(http.Header)
	reqHeader.Set("Accept", "application/json")
	reqHeader.Set("Scnt", scnt)
	reqHeader.Set("X-Apple-ID-Session-Id", session)
	reqHeader.Set("X-Apple-Widget-Key", "af1139274f266b22b68c2a3e7ad932cb3c0bbe854e13a79af78dcc73136882c3")
	reqHeader.Set("Origin", "https://account.apple.com")
	reqHeader.Set("Referer", "https://account.apple.com/")
	if cookie := cookiePairs(pageHeader); cookie != "" {
		reqHeader.Set("Cookie", cookie)
	}
	status, _, body, err = postJSON(ctx, c, "https://account.apple.com/account/validation/appleid", payload, reqHeader)
	if err != nil {
		return fromErr(err)
	}
	if appleLimited(status, body) {
		return finishLimited()
	}
	if status != http.StatusOK {
		return unexpected()
	}
	var resp struct {
		Valid *bool `json:"valid"`
		Used  *bool `json:"used"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Valid == nil || resp.Used == nil {
		return unexpected()
	}
	if !*resp.Valid {
		return checker.StatusError, "invalid email"
	}
	if *resp.Used {
		return checker.StatusFound, ""
	}
	return checker.StatusNotFound, ""
}

func appleLimited(status int, body []byte) bool {
	return status == http.StatusServiceUnavailable || limited(status, body)
}
