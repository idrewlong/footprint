// Package checker runs site checks concurrently and streams results.
package checker

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/idrewlong/footprint/internal/httpx"
)

const (
	// DefaultConcurrency is the number of checks allowed in flight.
	DefaultConcurrency = 16
	// DefaultTimeout is the deadline for a single site check.
	DefaultTimeout = 10 * time.Second
)

// Status is the outcome of one site check.
type Status string

const (
	StatusFound       Status = "found"
	StatusNotFound    Status = "not_found"
	StatusRateLimited Status = "rate_limited"
	StatusError       Status = "error"
)

// Result is one site's outcome. Duration is a Go duration in memory and
// milliseconds in JSON, under duration_ms.
//
// Method is register, login, password_reset, breach, or profile.
// Evidence is the signal that produced Status, such as "Signup endpoint
// said this email is already registered." A found status with an empty
// Evidence is a claim, not a finding.
type Result struct {
	Site        string        `json:"site"`
	Domain      string        `json:"domain"`
	Category    string        `json:"category"`
	Method      string        `json:"method"`
	Status      Status        `json:"status"`
	Evidence    string        `json:"evidence,omitempty"`
	DeleteURL   string        `json:"delete_url,omitempty"`
	SecurityURL string        `json:"security_url,omitempty"`
	ProfileURL  string        `json:"profile_url,omitempty"`
	Detail      string        `json:"detail,omitempty"`
	Duration    time.Duration `json:"-"`
}

type resultJSON struct {
	Site        string `json:"site"`
	Domain      string `json:"domain"`
	Category    string `json:"category"`
	Method      string `json:"method"`
	Status      Status `json:"status"`
	Evidence    string `json:"evidence,omitempty"`
	DeleteURL   string `json:"delete_url,omitempty"`
	SecurityURL string `json:"security_url,omitempty"`
	ProfileURL  string `json:"profile_url,omitempty"`
	Detail      string `json:"detail,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
}

// MarshalJSON encodes Duration as whole milliseconds.
func (r Result) MarshalJSON() ([]byte, error) {
	return json.Marshal(resultJSON{
		Site:        r.Site,
		Domain:      r.Domain,
		Category:    r.Category,
		Method:      r.Method,
		Status:      r.Status,
		Evidence:    r.Evidence,
		DeleteURL:   r.DeleteURL,
		SecurityURL: r.SecurityURL,
		ProfileURL:  r.ProfileURL,
		Detail:      r.Detail,
		DurationMS:  r.Duration.Milliseconds(),
	})
}

// UnmarshalJSON reads duration_ms back into a Duration.
func (r *Result) UnmarshalJSON(data []byte) error {
	var wire resultJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*r = Result{
		Site:        wire.Site,
		Domain:      wire.Domain,
		Category:    wire.Category,
		Method:      wire.Method,
		Status:      wire.Status,
		Evidence:    wire.Evidence,
		DeleteURL:   wire.DeleteURL,
		SecurityURL: wire.SecurityURL,
		ProfileURL:  wire.ProfileURL,
		Detail:      wire.Detail,
		Duration:    time.Duration(wire.DurationMS) * time.Millisecond,
	}
	return nil
}

// Site is one account check. Implementations live in pkg/sites.
type Site interface {
	Name() string
	Domain() string
	Category() string
	Method() string
	Check(ctx context.Context, c *http.Client, email string) Result
}

// Options overrides the default concurrency and per-check timeout.
// Zero values use the defaults.
type Options struct {
	Concurrency int
	Timeout     time.Duration
}

// Run checks every site in its own goroutine and sends each Result on the
// returned channel. The channel is closed after the last result.
// A slow site cannot hold the rest of the run past opts.Timeout.
func Run(ctx context.Context, email string, sites []Site, opts Options) <-chan Result {
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	out := make(chan Result)
	go func() {
		defer close(out)
		gate := httpx.NewGate(time.Minute)
		sem := make(chan struct{}, opts.Concurrency)
		var wg sync.WaitGroup
		for _, site := range sites {
			wg.Add(1)
			go func(site Site) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					out <- annotate(site, Result{Status: StatusError, Detail: "cancelled"})
					return
				}
				out <- checkOne(ctx, gate, site, email, opts.Timeout)
			}(site)
		}
		wg.Wait()
	}()
	return out
}

func checkOne(parent context.Context, gate *httpx.Gate, site Site, email string, timeout time.Duration) (res Result) {
	defer func() {
		if recover() != nil {
			res = annotate(site, Result{Status: StatusError, Detail: "check failed"})
		}
	}()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	start := time.Now()
	client := httpx.NewClient(httpx.Config{Timeout: timeout, Gate: gate})
	res = site.Check(ctx, client, email)
	if res.Duration == 0 {
		res.Duration = time.Since(start)
	}
	return annotate(site, res)
}

func annotate(site Site, res Result) Result {
	if res.Site == "" {
		res.Site = site.Name()
	}
	if res.Domain == "" {
		res.Domain = site.Domain()
	}
	if res.Category == "" {
		res.Category = site.Category()
	}
	if res.Method == "" {
		res.Method = site.Method()
	}
	if res.Status == "" {
		res.Status = StatusError
		if res.Detail == "" {
			res.Detail = "empty result"
		}
	}
	return res
}
