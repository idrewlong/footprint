package checker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type stub struct {
	name, domain, category, method string
	fn                             func(ctx context.Context, c *http.Client, email string) Result
}

func (s stub) Name() string     { return s.name }
func (s stub) Domain() string   { return s.domain }
func (s stub) Category() string { return s.category }
func (s stub) Method() string   { return s.method }
func (s stub) Check(ctx context.Context, c *http.Client, email string) Result {
	if s.fn == nil {
		return Result{Status: StatusNotFound}
	}
	return s.fn(ctx, c, email)
}

func collect(ch <-chan Result) []Result {
	var out []Result
	for res := range ch {
		out = append(out, res)
	}
	return out
}

func TestRunStreamsEverySite(t *testing.T) {
	sites := []Site{
		stub{name: "b", domain: "b.example", category: "dev", method: "register", fn: func(ctx context.Context, c *http.Client, email string) Result {
			return Result{Status: StatusFound, DeleteURL: "https://b.example/delete"}
		}},
		stub{name: "a", domain: "a.example", category: "social", method: "login", fn: func(ctx context.Context, c *http.Client, email string) Result {
			return Result{Status: StatusNotFound}
		}},
	}
	got := collect(Run(context.Background(), "a@b.co", sites, Options{Concurrency: 2, Timeout: time.Second}))
	if len(got) != 2 {
		t.Fatalf("got %d results", len(got))
	}
	names := map[string]Result{}
	for _, res := range got {
		names[res.Site] = res
		if res.Domain == "" || res.Category == "" || res.Method == "" {
			t.Fatalf("metadata not filled: %+v", res)
		}
		if res.Duration <= 0 {
			t.Fatalf("duration not set: %+v", res)
		}
	}
	if names["b"].Status != StatusFound || names["b"].DeleteURL == "" {
		t.Fatalf("found result: %+v", names["b"])
	}
	if names["a"].Status != StatusNotFound {
		t.Fatalf("miss result: %+v", names["a"])
	}
}

func TestRunCapsConcurrency(t *testing.T) {
	var current, max atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	var once atomic.Bool
	site := func(name string) Site {
		return stub{name: name, domain: name + ".example", category: "dev", method: "register", fn: func(ctx context.Context, c *http.Client, email string) Result {
			n := current.Add(1)
			for {
				old := max.Load()
				if n <= old || max.CompareAndSwap(old, n) {
					break
				}
			}
			if once.CompareAndSwap(false, true) {
				close(started)
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
			current.Add(-1)
			return Result{Status: StatusNotFound}
		}}
	}
	ch := Run(context.Background(), "a@b.co", []Site{site("a"), site("b"), site("c")}, Options{Concurrency: 2, Timeout: time.Second})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("checks did not start")
	}
	time.Sleep(30 * time.Millisecond)
	if max.Load() > 2 {
		t.Fatalf("concurrency peaked at %d", max.Load())
	}
	close(release)
	if len(collect(ch)) != 3 {
		t.Fatal("missing results")
	}
}

func TestRunTimeout(t *testing.T) {
	site := stub{name: "slow", domain: "slow.example", category: "dev", method: "register", fn: func(ctx context.Context, c *http.Client, email string) Result {
		<-ctx.Done()
		return Result{Status: StatusError, Detail: "timed out"}
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := collect(Run(ctx, "a@b.co", []Site{site}, Options{Concurrency: 1, Timeout: 40 * time.Millisecond}))
	if len(got) != 1 || got[0].Status != StatusError {
		t.Fatalf("got %+v", got)
	}
}

func TestRunRecoversPanic(t *testing.T) {
	site := stub{name: "boom", domain: "boom.example", category: "dev", method: "register", fn: func(ctx context.Context, c *http.Client, email string) Result {
		panic("site bug")
	}}
	got := collect(Run(context.Background(), "a@b.co", []Site{site}, Options{Concurrency: 1, Timeout: time.Second}))
	if len(got) != 1 || got[0].Status != StatusError || got[0].Site != "boom" {
		t.Fatalf("got %+v", got)
	}
}

func TestRunBacksOffDomain(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	check := func(name string) Site {
		return stub{name: name, domain: "example.com", category: "dev", method: "login", fn: func(ctx context.Context, c *http.Client, email string) Result {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
			if err != nil {
				return Result{Status: StatusError, Detail: "request failed"}
			}
			resp, err := c.Do(req)
			if err != nil {
				return Result{Status: StatusError, Detail: "request failed"}
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				return Result{Status: StatusRateLimited}
			}
			return Result{Status: StatusNotFound}
		}}
	}
	got := collect(Run(context.Background(), "a@b.co", []Site{check("one"), check("two")}, Options{Concurrency: 1, Timeout: time.Second}))
	if hits.Load() != 1 {
		t.Fatalf("server hits = %d, want 1", hits.Load())
	}
	if len(got) != 2 {
		t.Fatalf("got %d results", len(got))
	}
	for _, res := range got {
		if res.Status != StatusRateLimited {
			t.Fatalf("status %s, want rate_limited", res.Status)
		}
	}
}

func TestResultJSONUsesMilliseconds(t *testing.T) {
	res := Result{
		Site:     "adobe",
		Domain:   "adobe.com",
		Category: "productivity",
		Method:   "login",
		Status:   StatusFound,
		Duration: 1500 * time.Millisecond,
	}
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["duration_ms"] != float64(1500) {
		t.Fatalf("duration_ms = %v", wire["duration_ms"])
	}
	var back Result
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Duration != 1500*time.Millisecond {
		t.Fatalf("round trip duration = %s", back.Duration)
	}
}
