package sites

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func init() { Register(&xposedornot{}) }

// xposedornot asks the public breach-name API whether this email appears
// in a known breach. The response used here is a list of breach titles.
// Password values, hashes, and other stolen fields are not requested and
// are not copied if a response contains them.
type xposedornot struct{}

func (xposedornot) Name() string     { return "xposedornot" }
func (xposedornot) Domain() string   { return "xposedornot.com" }
func (xposedornot) Category() string { return "security" }
func (xposedornot) Method() string   { return "breach" }

func (s *xposedornot) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	res := s.result(status, detail, time.Since(start))
	if status == checker.StatusFound {
		res.Breaches = breachHitsFromNames(detail)
	}
	return res
}

func (s *xposedornot) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:     "xposedornot",
		domain:   "xposedornot.com",
		category: "security",
		method:   "breach",
	}.result(status, detail, elapsed)
}

func (s *xposedornot) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	endpoint := "https://api.xposedornot.com/v1/check-email/" + url.PathEscape(email)
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
		Breaches [][]string `json:"breaches"`
		Error    string     `json:"Error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return unexpected()
	}
	if strings.EqualFold(resp.Error, "not found") {
		return checker.StatusNotFound, ""
	}
	names := breachNames(resp.Breaches)
	if len(names) > 0 {
		return checker.StatusFound, strings.Join(names, ", ")
	}
	if status == http.StatusNotFound {
		return checker.StatusNotFound, ""
	}
	return unexpected()
}

func breachNames(groups [][]string) []string {
	seen := map[string]struct{}{}
	var names []string
	for _, group := range groups {
		for _, name := range group {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
