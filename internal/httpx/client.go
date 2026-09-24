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

// browser is one desktop browser identity. Chromium browsers send client
// hints that must agree with the user agent. Firefox sends none.
type browser struct {
	ua       string
	secCHUA  string
	platform string
}

// browsers are current desktop releases (Chrome and Edge 153, Firefox 156,
// September 2026). Each client picks one and keeps it for every request in
// that check. Update these with each few browser releases; a stale version
// is an easy bot signal.
var browsers = []browser{
	{
		ua:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
		secCHUA:  `"Chromium";v="153", "Google Chrome";v="153", "Not.A/Brand";v="99"`,
		platform: `"macOS"`,
	},
	{
		ua:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
		secCHUA:  `"Chromium";v="153", "Google Chrome";v="153", "Not.A/Brand";v="99"`,
		platform: `"Windows"`,
	},
	{
		ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:156.0) Gecko/20100101 Firefox/156.0",
	},
	{
		ua:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0",
		secCHUA:  `"Chromium";v="153", "Microsoft Edge";v="153", "Not.A/Brand";v="99"`,
		platform: `"Windows"`,
	},
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
// Transport is shared across clients so checks reuse connections; the
// owner closes its idle connections. A nil Transport gets a new one.
type Config struct {
	Timeout   time.Duration
	Gate      *Gate
	Transport http.RoundTripper
}

// NewTransport returns a transport with the default settings. Share one
// across the checks of a run and call CloseIdleConnections when done.
func NewTransport() *http.Transport {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		return transport.Clone()
	}
	return &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true}
}

// NewClient returns a client that does not follow redirects.
// Redirect targets are a different page, and treating them as the
// check response would hide a block or an error.
// Each client has its own cookie jar, even when the transport is shared.
func NewClient(cfg Config) *http.Client {
	base := cfg.Transport
	if base == nil {
		base = NewTransport()
	}
	client := &http.Client{
		Timeout: cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &roundTripper{
			base:    base,
			gate:    cfg.Gate,
			browser: browsers[rand.IntN(len(browsers))],
		},
	}
	if jar, err := cookiejar.New(nil); err == nil {
		client.Jar = jar
	}
	return client
}

type roundTripper struct {
	base    http.RoundTripper
	gate    *Gate
	browser browser
}

func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	// Client hints go out only with our own user agent. A check that sets
	// its own user agent is not posing as a browser.
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.browser.ua)
		if t.browser.secCHUA != "" {
			setDefault(req.Header, "Sec-CH-UA", t.browser.secCHUA)
			setDefault(req.Header, "Sec-CH-UA-Mobile", "?0")
			setDefault(req.Header, "Sec-CH-UA-Platform", t.browser.platform)
		}
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
	// A challenge flagged in headers can arrive with a body that names no
	// marker, so turn it into a 429 that every check already handles.
	if limitedHeader(resp.StatusCode, resp.Header) {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		t.gate.Mark(host)
		return tooMany(req), nil
	}
	peek := peekBody(resp)
	if IsLimited(resp.StatusCode, peek) {
		t.gate.Mark(host)
	}
	return resp, nil
}

func setDefault(h http.Header, key, value string) {
	if h.Get(key) == "" {
		h.Set(key, value)
	}
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
//
// Generic phrases such as "rate limit" also show up in ordinary pages and
// scripts, and one false match backs off the whole domain. So a 2xx
// response is checked only when it is HTML, and then only for markers
// that appear on challenge pages alone or for a phrase in the page title.
// Error responses are checked for every marker anywhere in the body.
func IsLimited(status int, body []byte) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	text := strings.ToLower(string(body))
	if status < 200 || status > 299 {
		return containsAny(text, challengeMarkers) || containsAny(text, limitPhrases)
	}
	if !isHTML(body) {
		return false
	}
	return containsAny(text, challengeMarkers) || containsAny(htmlTitle(text), limitPhrases)
}

// challengeMarkers appear on bot-check pages and not on the pages they
// protect. DataDome's ordinary script tag loads from js.datadome.co, so
// the bare word "datadome" is not a marker.
var challengeMarkers = []string{
	"captcha-delivery.com",
	"please enable js and disable any ad blocker",
	"cf-browser-verification",
	"_cf_chl_opt",
}

// limitPhrases are wording that block pages use and ordinary pages can
// also contain.
var limitPhrases = []string{
	"datadome",
	"var dd=",
	"unusual traffic",
	"too many requests",
	"just a moment",
	"rate limit",
}

// limitedHeader reports a challenge that the response headers announce.
// Cloudflare marks challenge pages with cf-mitigated. DataDome blocks with
// a 403 that carries its X-DataDome header.
func limitedHeader(status int, header http.Header) bool {
	if strings.EqualFold(header.Get("Cf-Mitigated"), "challenge") {
		return true
	}
	return status == http.StatusForbidden && header.Get("X-Datadome") != ""
}

func containsAny(text string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func isHTML(body []byte) bool {
	return strings.HasPrefix(http.DetectContentType(body), "text/html")
}

// htmlTitle returns the text of the first <title> element in lowered HTML.
func htmlTitle(text string) string {
	start := strings.Index(text, "<title")
	if start < 0 {
		return ""
	}
	open := strings.IndexByte(text[start:], '>')
	if open < 0 {
		return ""
	}
	rest := text[start+open+1:]
	if end := strings.Index(rest, "</title>"); end >= 0 {
		return rest[:end]
	}
	return ""
}
