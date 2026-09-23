package sites

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&xnxx{}) }

// xnxx uses the same public signup email check as its sibling network.
// Mapping matches interpretXVideosEmailCheck: result true is available,
// invalid-email messages are errors, and any other result false message
// is a hit (inverse of the live available response). No mail is sent.
type xnxx struct{}

func (xnxx) Name() string     { return "xnxx" }
func (xnxx) Domain() string   { return "xnxx.com" }
func (xnxx) Category() string { return "adult" }
func (xnxx) Method() string   { return "register" }

func (s *xnxx) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *xnxx) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "xnxx",
		domain:        "xnxx.com",
		category:      "adult",
		method:        "register",
		deleteURL:     "https://info.xnxx.com/legal/privacy",
		securityURL:   "https://www.xnxx.com/account/security",
		foundEvidence: "Signup endpoint said this email is already taken.",
		missEvidence:  "Signup endpoint said this email can still be registered.",
	}.result(status, detail, elapsed)
}

func (s *xnxx) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	endpoint := "https://www.xnxx.com/account/checkemail?" + url.Values{"email": {email}}.Encode()
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
