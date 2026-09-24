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
// Method is register, login, password_reset, breach, profile, dns, infra, or entity.
// Evidence is the signal that produced Status, such as "Signup endpoint
// said this email is already registered." A found status with an empty
// Evidence is a claim, not a finding.
//
// Breaches lists the breaches a breach check named, with dates when the
// source gives them. Dates are metadata, not stolen values, so they are safe
// to keep and let the report order breaches on a timeline.
type Result struct {
	Site        string        `json:"site"`
	Domain      string        `json:"domain"`
	Category    string        `json:"category"`
	Method      string        `json:"method"`
	Status      Status        `json:"status"`
	Evidence    string        `json:"evidence,omitempty"`
	Confidence  string        `json:"confidence,omitempty"`
	DeleteURL   string        `json:"delete_url,omitempty"`
	SecurityURL string        `json:"security_url,omitempty"`
	ProfileURL  string        `json:"profile_url,omitempty"`
	Detail      string        `json:"detail,omitempty"`
	Breaches    []BreachHit   `json:"breaches,omitempty"`
	Duration    time.Duration `json:"-"`
}

// BreachHit is one named breach. Date is the breach date in whatever
// granularity the source reports (often YYYY-MM), or empty when unknown. It
// never carries a password, hash, or other stolen value.
type BreachHit struct {
	Name string `json:"name"`
	Date string `json:"date,omitempty"`
}

type resultJSON struct {
	Site        string      `json:"site"`
	Domain      string      `json:"domain"`
	Category    string      `json:"category"`
	Method      string      `json:"method"`
	Status      Status      `json:"status"`
	Evidence    string      `json:"evidence,omitempty"`
	Confidence  string      `json:"confidence,omitempty"`
	DeleteURL   string      `json:"delete_url,omitempty"`
	SecurityURL string      `json:"security_url,omitempty"`
	ProfileURL  string      `json:"profile_url,omitempty"`
	Detail      string      `json:"detail,omitempty"`
	Breaches    []BreachHit `json:"breaches,omitempty"`
	DurationMS  int64       `json:"duration_ms"`
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
		Confidence:  r.Confidence,
		DeleteURL:   r.DeleteURL,
		SecurityURL: r.SecurityURL,
		ProfileURL:  r.ProfileURL,
		Detail:      r.Detail,
		Breaches:    r.Breaches,
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
		Confidence:  wire.Confidence,
		DeleteURL:   wire.DeleteURL,
		SecurityURL: wire.SecurityURL,
		ProfileURL:  wire.ProfileURL,
		Detail:      wire.Detail,
		Breaches:    wire.Breaches,
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

// MethodPasswordReset drives a site's password-reset flow. It is the one
// method that can send mail to the address being checked, so it is treated
// as an alerting method: the account owner may learn of the lookup.
const MethodPasswordReset = "password_reset"

// Notifies reports whether a method can alert the address being checked,
// for example by sending it a password-reset email. Passive checks (signup,
// login, breach, profile lookups) never touch the target's mailbox. Callers
// scan passively by default and run alerting checks only on explicit opt-in.
func Notifies(method string) bool {
	return method == MethodPasswordReset
}

// Confidence levels rank how directly a found signal ties the address to an
// account. They are set only on found rows; other statuses leave it empty.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// Confidence rates a found signal. A direct account signal (a signup or
// login lookup, or a reset flow) is high. A breach corpus or a profile that
// matches a username the operator supplied is medium. A profile matched only
// from the mailbox name is low, since the username was inferred, not given.
// A non-found status returns an empty string.
func Confidence(method string, status Status, fromMailbox bool) string {
	if status != StatusFound {
		return ""
	}
	switch method {
	case "register", "login", MethodPasswordReset:
		return ConfidenceHigh
	case "breach":
		return ConfidenceMedium
	case "profile":
		if fromMailbox {
			return ConfidenceLow
		}
		return ConfidenceMedium
	default:
		return ""
	}
}

// Options overrides the default concurrency and per-check timeout.
// Zero values use the defaults.
type Options struct {
	Concurrency int
	Timeout     time.Duration
	// Transport, when set, is shared by every check so all traffic goes
	// through it (for example a SOCKS5 or Tor proxy). The caller owns it and
	// closes idle connections. When nil, Run builds and closes its own.
	Transport http.RoundTripper
}

// Run checks every site in its own goroutine and sends each Result on the
// returned channel. The channel is closed after the last result.
// A slow site cannot hold the rest of the run past opts.Timeout.
//
// The channel holds one slot per site, so a caller that stops reading
// early does not strand the check goroutines. Cancel ctx to stop checks
// that are still running.
func Run(ctx context.Context, email string, sites []Site, opts Options) <-chan Result {
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	out := make(chan Result, len(sites))
	go func() {
		defer close(out)
		gate := httpx.NewGate(time.Minute)
		// One transport per run lets checks reuse connections and TLS
		// sessions. Each check still gets its own cookie jar. A caller can
		// supply one (a proxy); otherwise Run owns and closes its own.
		transport := opts.Transport
		if transport == nil {
			owned := httpx.NewTransport()
			defer owned.CloseIdleConnections()
			transport = owned
		}
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
				out <- checkOne(ctx, transport, gate, site, email, opts.Timeout)
			}(site)
		}
		wg.Wait()
	}()
	return out
}

func checkOne(parent context.Context, transport http.RoundTripper, gate *httpx.Gate, site Site, email string, timeout time.Duration) (res Result) {
	defer func() {
		if recover() != nil {
			res = annotate(site, Result{Status: StatusError, Detail: "check failed"})
		}
	}()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	start := time.Now()
	client := httpx.NewClient(httpx.Config{Timeout: timeout, Gate: gate, Transport: transport})
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
