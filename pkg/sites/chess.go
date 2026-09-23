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

func init() { Register(&chess{}) }

// chess reads the public signup callback that reports whether an email
// can still be registered. An invalid address is an error, not a miss.
type chess struct{}

func (chess) Name() string     { return "chess" }
func (chess) Domain() string   { return "chess.com" }
func (chess) Category() string { return "entertainment" }
func (chess) Method() string   { return "register" }

func (s *chess) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *chess) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:        "chess",
		domain:      "chess.com",
		category:    "entertainment",
		method:      "register",
		deleteURL:   "https://www.chess.com/settings",
		securityURL: "https://www.chess.com/settings",
	}.result(status, detail, elapsed)
}

func (s *chess) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	endpoint := "https://www.chess.com/callback/email/available?email=" + url.QueryEscape(email)
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := get(ctx, c, endpoint, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	var resp struct {
		Available *bool  `json:"isEmailAvailable"`
		Reason    string `json:"reason"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Available == nil {
		return unexpected()
	}
	if *resp.Available {
		return checker.StatusNotFound, ""
	}
	reason := strings.ToLower(resp.Reason)
	switch {
	case strings.Contains(reason, "invalid"):
		return checker.StatusError, "invalid email"
	case strings.Contains(reason, "in use") || strings.Contains(reason, "taken") || strings.Contains(reason, "registered") || strings.Contains(reason, "already"):
		return checker.StatusFound, ""
	default:
		return unexpected()
	}
}
