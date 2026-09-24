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

func init() { Register(&ea{}) }

// ea loads the public create-account session, then asks checkEmailExisted
// whether the address is already registered. The lookup does not send mail.
type ea struct{}

func (ea) Name() string     { return "ea" }
func (ea) Domain() string   { return "ea.com" }
func (ea) Category() string { return "entertainment" }
func (ea) Method() string   { return "register" }

func (s *ea) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *ea) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "ea",
		domain:        "ea.com",
		category:      "entertainment",
		method:        "register",
		deleteURL:     "https://help.ea.com/en/help/account/delete-your-ea-account/",
		securityURL:   "https://myaccount.ea.com/cp-ui/security/index",
		foundEvidence: "Create-account check said this email is already registered.",
		missEvidence:  "Create-account check said this email is not registered.",
	}.result(status, detail, elapsed)
}

func (s *ea) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	return checkEAEmail(ctx, c, email)
}

func checkEAEmail(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	header := make(http.Header)
	header.Set("Accept", "text/html")
	status, respHeader, body, err := get(ctx, c, "https://signin.ea.com/p/juno/create", header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	cookie := eaSessionCookie(respHeader)
	if cookie == "" {
		return checker.StatusError, "create page did not include a session"
	}
	endpoint := "https://signin.ea.com/p/ajax/user/checkEmailExisted?email=" + url.QueryEscape(email)
	reqHeader := make(http.Header)
	reqHeader.Set("Accept", "application/json")
	reqHeader.Set("X-Requested-With", "XMLHttpRequest")
	reqHeader.Set("Referer", "https://signin.ea.com/p/juno/create")
	reqHeader.Set("Cookie", cookie)
	status, _, body, err = get(ctx, c, endpoint, reqHeader)
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
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Message == "" {
		return unexpected()
	}
	switch strings.ToLower(resp.Message) {
	case "register_email_not_existed":
		return checker.StatusNotFound, ""
	case "register_email_existed":
		return checker.StatusFound, ""
	case "register_email_invalid":
		return checker.StatusError, "invalid email"
	default:
		return unexpected()
	}
}

func eaSessionCookie(header http.Header) string {
	session := csrfCookie(header, "JSESSIONID")
	signin := csrfCookie(header, "signin-cookie")
	if session == "" || signin == "" {
		return ""
	}
	return "JSESSIONID=" + session + "; signin-cookie=" + signin
}
