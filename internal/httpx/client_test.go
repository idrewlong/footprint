package httpx

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsLimited(t *testing.T) {
	if !IsLimited(http.StatusTooManyRequests, []byte("nope")) {
		t.Fatal("429 should be limited")
	}
	if !IsLimited(http.StatusForbidden, []byte("<html>Please enable JS and disable any ad blocker</html>")) {
		t.Fatal("block page should be limited")
	}
	if IsLimited(http.StatusForbidden, []byte(`{"message":"CSRF token missing"}`)) {
		t.Fatal("a JSON error is not a block page")
	}
	if IsLimited(http.StatusOK, []byte(`{"exists":false}`)) {
		t.Fatal("a normal body is not limited")
	}
	if IsLimited(http.StatusOK, []byte(`{"exists":false,"hint":"too many requests will be rate limited"}`)) {
		t.Fatal("a 2xx JSON body is not checked for phrases")
	}
	page := `<!doctype html><html><head><title>Sign in</title><script>var rateLimit="rate limit";</script></head><body>Just a moment while we load</body></html>`
	if IsLimited(http.StatusOK, []byte(page)) {
		t.Fatal("a phrase in an ordinary page's script or body is not a block")
	}
	if !IsLimited(http.StatusOK, []byte(`<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>`)) {
		t.Fatal("a 2xx challenge page title should be limited")
	}
	if !IsLimited(http.StatusOK, []byte(`<html><script src="https://geo.captcha-delivery.com/captcha/"></script></html>`)) {
		t.Fatal("a 2xx captcha page should be limited")
	}
	if !IsLimited(http.StatusServiceUnavailable, []byte(`{"error":"rate limit exceeded"}`)) {
		t.Fatal("an error body naming a rate limit should be limited")
	}
}

func TestChallengeHeaderBecomes429(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	client := NewClient(Config{Timeout: time.Second, Gate: NewGate(time.Minute)})
	for i := 0; i < 2; i++ {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("request %d status %d", i, resp.StatusCode)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("server hits = %d, want 1", hits.Load())
	}
}

func TestClientHintsMatchUserAgent(t *testing.T) {
	type seen struct{ ua, chua, platform string }
	got := make(chan seen, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.Header.Get("User-Agent"), r.Header.Get("Sec-CH-UA"), r.Header.Get("Sec-CH-UA-Platform")}
	}))
	defer srv.Close()

	for i := 0; i < 20; i++ {
		resp, err := NewClient(Config{Timeout: time.Second}).Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		s := <-got
		chromium := strings.Contains(s.ua, "Chrome/")
		if chromium != (s.chua != "") || chromium != (s.platform != "") {
			t.Fatalf("hints do not match user agent: %+v", s)
		}
		if chromium && !strings.Contains(s.chua, `v="`+chromeMajor(s.ua)+`"`) {
			t.Fatalf("sec-ch-ua version differs from user agent: %+v", s)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("User-Agent", "footprint")
	resp, err := NewClient(Config{Timeout: time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if s := <-got; s.chua != "" {
		t.Fatalf("custom user agent should not carry client hints: %+v", s)
	}
}

func chromeMajor(ua string) string {
	rest := ua[strings.Index(ua, "Chrome/")+len("Chrome/"):]
	return rest[:strings.IndexByte(rest, '.')]
}

func TestSharedTransportReusesConnections(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	transport := NewTransport()
	defer transport.CloseIdleConnections()
	for i := 0; i < 5; i++ {
		resp, err := NewClient(Config{Timeout: time.Second, Transport: transport}).Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if conns.Load() != 1 {
		t.Fatalf("connections = %d, want 1", conns.Load())
	}
}

func TestGateSkipsSecondRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	gate := NewGate(time.Minute)
	client := NewClient(Config{Timeout: time.Second, Gate: gate})
	for i := 0; i < 2; i++ {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("request %d status %d", i, resp.StatusCode)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("server hits = %d, want 1", hits.Load())
	}
}

func TestNewTransportProxyEmptyIsDirect(t *testing.T) {
	tr, err := NewTransportProxy("")
	if err != nil {
		t.Fatalf("empty proxy: %v", err)
	}
	if tr == nil {
		t.Fatal("nil transport")
	}
}

func TestNewTransportProxyHTTP(t *testing.T) {
	tr, err := NewTransportProxy("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("http proxy: %v", err)
	}
	if tr.Proxy == nil {
		t.Fatal("http proxy did not set Proxy")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	u, err := tr.Proxy(req)
	if err != nil || u == nil || u.Host != "127.0.0.1:8080" {
		t.Fatalf("proxy url = %v, %v", u, err)
	}
}

func TestNewTransportProxySOCKS5(t *testing.T) {
	tr, err := NewTransportProxy("socks5h://127.0.0.1:9050")
	if err != nil {
		t.Fatalf("socks5h proxy: %v", err)
	}
	if tr.DialContext == nil {
		t.Fatal("socks5 proxy did not set DialContext")
	}
	if tr.Proxy != nil {
		t.Fatal("socks5 proxy must clear the HTTP proxy")
	}
}

func TestNewTransportProxyRejectsUnknownScheme(t *testing.T) {
	if _, err := NewTransportProxy("ftp://127.0.0.1:21"); err == nil {
		t.Fatal("unsupported scheme was accepted")
	}
}
