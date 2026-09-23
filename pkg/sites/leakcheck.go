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

func init() { Register(&leakcheck{}) }

// leakcheck reads the public breach-name API. A hit is the list of source
// names. Field labels and any password, hash, or other stolen value in the
// payload are not copied.
type leakcheck struct{}

func (leakcheck) Name() string     { return "leakcheck" }
func (leakcheck) Domain() string   { return "leakcheck.io" }
func (leakcheck) Category() string { return "security" }
func (leakcheck) Method() string   { return "breach" }

func (s *leakcheck) Check(ctx context.Context, c *http.Client, email string) checker.Result {
	start := time.Now()
	status, detail := s.lookup(ctx, c, email)
	return s.result(status, detail, time.Since(start))
}

func (s *leakcheck) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:     "leakcheck",
		domain:   "leakcheck.io",
		category: "security",
		method:   "breach",
	}.result(status, detail, elapsed)
}

func (s *leakcheck) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string) {
	endpoint := "https://leakcheck.io/api/public?check=" + url.QueryEscape(email)
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
		Success bool   `json:"success"`
		Error   string `json:"error"`
		Sources []struct {
			Name string `json:"name"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return unexpected()
	}
	if !resp.Success && strings.EqualFold(resp.Error, "not found") {
		return checker.StatusNotFound, ""
	}
	if !resp.Success || status != http.StatusOK {
		return unexpected()
	}
	names := uniqueNames(func() []string {
		out := make([]string, 0, len(resp.Sources))
		for _, source := range resp.Sources {
			out = append(out, source.Name)
		}
		return out
	}())
	if len(names) == 0 {
		return unexpected()
	}
	return checker.StatusFound, strings.Join(names, ", ")
}

func uniqueNames(raw []string) []string {
	seen := map[string]struct{}{}
	var names []string
	for _, name := range raw {
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
	sort.Strings(names)
	return names
}
