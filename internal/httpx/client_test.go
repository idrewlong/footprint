package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
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
