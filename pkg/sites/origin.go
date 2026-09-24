package sites

import (
	"context"
	"net/http"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&origin{}) }

// origin uses the same EA create-account email check. Origin accounts are
// EA accounts; the public lookup does not send mail.
type origin struct{}

func (origin) Name() string     { return "origin" }
func (origin) Domain() string   { return "origin.com" }
func (origin) Category() string { return "entertainment" }
func (origin) Method() string   { return "register" }

func (s *origin) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *origin) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:          "origin",
		domain:        "origin.com",
		category:      "entertainment",
		method:        "register",
		deleteURL:     "https://help.ea.com/en/help/account/delete-your-ea-account/",
		securityURL:   "https://myaccount.ea.com/cp-ui/security/index",
		foundEvidence: "EA create-account check said this email is already registered.",
		missEvidence:  "EA create-account check said this email is not registered.",
	}.result(status, detail, elapsed)
}

func (s *origin) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	return checkEAEmail(ctx, c, email)
}
