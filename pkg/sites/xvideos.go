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

func init() { Register(&xvideos{}) }

// xvideos GETs the public signup email check. result true means the address
// can still be registered. result false with an invalid-email message is an
// error. Any other result false message means the address is already taken
// (inverse of the live available response). The request does not send mail.
type xvideos struct{}

func (xvideos) Name() string     { return "xvideos" }
func (xvideos) Domain() string   { return "xvideos.com" }
func (xvideos) Category() string { return "adult" }
func (xvideos) Method() string   { return "register" }

func (s *xvideos) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *xvideos) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "xvideos",
		domain:        "xvideos.com",
		category:      "adult",
		method:        "register",
		deleteURL:     "https://info.xvideos.com/legal/privacy",
		securityURL:   "https://www.xvideos.com/account/security",
		foundEvidence: "Signup endpoint said this email is already taken.",
		missEvidence:  "Signup endpoint said this email can still be registered.",
	}.result(status, detail, elapsed)
}

func (s *xvideos) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	endpoint := "https://www.xvideos.com/account/checkemail?" + url.Values{"email": {email}}.Encode()
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := get(ctx, c, endpoint, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	return interpretXVideosEmailCheck(status, body)
}

func interpretXVideosEmailCheck(status int, body []byte) (checker.Status, string) {
	if status != http.StatusOK {
		return unexpected()
	}
	var resp struct {
		Result  *bool  `json:"result"`
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Result == nil {
		return unexpected()
	}
	if *resp.Result {
		return checker.StatusNotFound, ""
	}
	message := strings.ToLower(resp.Message)
	if resp.Code == 1 || strings.Contains(message, "invalid") {
		return checker.StatusError, "invalid email"
	}
	if message == "" {
		return unexpected()
	}
	return checker.StatusFound, ""
}
