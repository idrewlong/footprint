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
	status, detail, hits := s.lookup(ctx, c, email)
	res := s.result(status, detail, time.Since(start))
	res.Breaches = hits
	return res
}

func (s *leakcheck) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	return base{
		name:     "leakcheck",
		domain:   "leakcheck.io",
		category: "security",
		method:   "breach",
	}.result(status, detail, elapsed)
}

func (s *leakcheck) lookup(ctx context.Context, c *http.Client, email string) (checker.Status, string, []checker.BreachHit) {
	endpoint := "https://leakcheck.io/api/public?check=" + url.QueryEscape(email)
	header := make(http.Header)
	header.Set("Accept", "application/json")
	status, _, body, err := get(ctx, c, endpoint, header)
	if err != nil {
		st, detail := fromErr(err)
		return st, detail, nil
	}
	if limited(status, body) {
		st, detail := finishLimited()
		return st, detail, nil
	}
	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
		Sources []struct {
			Name string `json:"name"`
			Date string `json:"date"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		st, detail := unexpected()
		return st, detail, nil
	}
	if !resp.Success && strings.EqualFold(resp.Error, "not found") {
		return checker.StatusNotFound, "", nil
	}
	if !resp.Success || status != http.StatusOK {
		st, detail := unexpected()
		return st, detail, nil
	}
	// Keep the earliest date seen for each named source. Dates are breach
	// metadata, never a stolen value.
	dateByName := map[string]string{}
	var order []string
	for _, source := range resp.Sources {
		name := strings.TrimSpace(source.Name)
		if name == "" {
			continue
		}
		if _, ok := dateByName[name]; !ok {
			order = append(order, name)
		}
		if cur := dateByName[name]; cur == "" || (source.Date != "" && source.Date < cur) {
			dateByName[name] = strings.TrimSpace(source.Date)
		}
	}
	if len(order) == 0 {
		st, detail := unexpected()
		return st, detail, nil
	}
	sort.Strings(order)
	hits := make([]checker.BreachHit, 0, len(order))
	for _, name := range order {
		hits = append(hits, checker.BreachHit{Name: name, Date: dateByName[name]})
	}
	return checker.StatusFound, strings.Join(order, ", "), hits
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
