package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&hibp{}) }

// hibp reads Have I Been Pwned's breached-account API. The default response
// is breach names only. The call is skipped unless HIBP_API_KEY is set, so a
// missing key is an error rather than a miss. The full breach model, which
// describes leaked data classes, is not requested.
type hibp struct{}

func (hibp) Name() string     { return "hibp" }
func (hibp) Domain() string   { return "haveibeenpwned.com" }
func (hibp) Category() string { return "security" }
func (hibp) Method() string   { return "breach" }

func (s *hibp) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	res := s.result(status, detail, time.Since(start))
	if status == checker.StatusFound {
		res.Breaches = breachHitsFromNames(detail)
	}
	return res
}

func (s *hibp) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:     "hibp",
		domain:   "haveibeenpwned.com",
		category: "security",
		method:   "breach",
	}.result(status, detail, elapsed)
}

func (s *hibp) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	key := os.Getenv("HIBP_API_KEY")
	if key == "" {
		return checker.StatusError, "hibp api key required"
	}
	endpoint := "https://haveibeenpwned.com/api/v3/breachedaccount/" + url.PathEscape(email)
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("hibp-api-key", key)
	header.Set("User-Agent", "footprint")
	status, _, body, err := get(ctx, c, endpoint, header)
	if err != nil {
		return fromErr(err)
	}
	if limited(status, body) {
		return finishLimited()
	}
	if status == http.StatusNotFound {
		return checker.StatusNotFound, ""
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return checker.StatusError, "hibp api key rejected"
	}
	if status != http.StatusOK {
		return unexpected()
	}
	var breaches []struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(body, &breaches); err != nil {
		return unexpected()
	}
	names := uniqueNames(func() []string {
		out := make([]string, 0, len(breaches))
		for _, breach := range breaches {
			out = append(out, breach.Name)
		}
		return out
	}())
	if len(names) == 0 {
		return unexpected()
	}
	return checker.StatusFound, strings.Join(names, ", ")
}
