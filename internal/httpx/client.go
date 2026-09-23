// Package httpx is the shared HTTP client used by site checks.
// It rotates browser user agents, keeps a cookie jar per client, and
// backs off a domain after a 429 or a known block page.
package httpx

import (
	"bytes"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

// userAgents are ordinary desktop browsers. Each client picks one and
// keeps it for every request in that check.
var userAgents = []string{
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
}

// Gate remembers domains that recently answered with a block, so a later
// check against the same host is not reported as a miss.
type Gate struct {
	mu    sync.Mutex
	until map[string]time.Time
	wait  time.Duration
}

// NewGate returns a gate that skips a domain for backoff after a block.
func NewGate(backoff time.Duration) *Gate {
	if backoff <= 0 {
		backoff = time.Minute
	}
	return &Gate{until: map[string]time.Time{}, wait: backoff}
}

// Mark starts the backoff window for host.
func (g *Gate) Mark(host string) {
	if g == nil || host == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.until[strings.ToLower(host)] = time.Now().Add(g.wait)
}

// Limited reports whether host is still inside its backoff window.
func (g *Gate) Limited(host string) bool {
	if g == nil || host == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.until[strings.ToLower(host)]
	return ok && time.Now().Before(until)
}

// Config controls a client created for one site check.
type Config struct {
	Timeout time.Duration
	Gate    *Gate
}

// NewClient returns a client that does not follow redirects.
// Redirect targets are a different page, and treating them as the
// check response would hide a block or an error.
func NewClient(cfg Config) *http.Client {
	var base http.RoundTripper
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		base = transport.Clone()
	} else {
		base = http.DefaultTransport
	}
	client := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &roundTripper{
			base: base,
			gate: cfg.Gate,
			ua:   userAgents[rand.IntN(len(userAgents))],
		},
	}
	if jar, err := cookiejar.New(nil); err == nil {
		client.Jar = jar
	}
	return client
}

type roundTripper struct {
	base http.RoundTripper
	gate *Gate
	ua   string
}

func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.ua)
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	host := req.URL.Hostname()
	if t.gate != nil && t.gate.Limited(host) {
		return tooMany(req), nil
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	peek := peekBody(resp)
	if IsLimited(resp.StatusCode, peek) && t.gate != nil {
		t.gate.Mark(host)
	}
	return resp, nil
}

func peekBody(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	orig := resp.Body
	buf, _ := io.ReadAll(io.LimitReader(orig, 8192))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), orig), orig}
	return buf
}

func tooMany(req *http.Request) *http.Response {
	const body = "too many requests"
	return &http.Response{
		StatusCode:    http.StatusTooManyRequests,
		Status:        "429 Too Many Requests",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// IsLimited reports whether the response is a 429 or a known interstitial
// (bot check, captcha, or "try again" page). Callers must not turn that
// into not_found.
func IsLimited(status int, body []byte) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	text := strings.ToLower(string(body))
	markers := []string{
		"datadome",
		"captcha-delivery.com",
		"please enable js and disable any ad blocker",
		"unusual traffic",
		"too many requests",
		"just a moment",
		"cf-browser-verification",
		"rate limit",
		"var dd=",
	}
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
