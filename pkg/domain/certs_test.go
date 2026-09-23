package domain

import (
	"context"
	"strings"
	"testing"

	"github.com/idrewlong/footprint/pkg/checker"
)

func TestCertificatesCountsNames(t *testing.T) {
	body := []byte(`[{"common_name":"example.com"},{"common_name":"example.com"},{"common_name":"www.example.com"}]`)
	var called string
	row := Certificates(context.Background(), func(ctx context.Context, url string) ([]byte, int, error) {
		called = url
		return body, 200, nil
	}, "example.com")
	if row.Status != checker.StatusFound || row.Method != "dns" {
		t.Fatalf("%+v", row)
	}
	if !strings.Contains(row.Evidence, "crt.sh") || !strings.Contains(row.Detail, "example.com") {
		t.Fatalf("%+v", row)
	}
	if !strings.Contains(called, "q=example.com") || strings.Contains(called, "%") {
		t.Fatalf("url %s", called)
	}
}

func TestCertificatesTimeoutIsError(t *testing.T) {
	row := Certificates(context.Background(), func(ctx context.Context, url string) ([]byte, int, error) {
		return nil, 0, context.DeadlineExceeded
	}, "example.com")
	if row.Status != checker.StatusError || row.Evidence != "" {
		t.Fatalf("%+v", row)
	}
}

func TestCertificatesEmptyIsNotFound(t *testing.T) {
	row := Certificates(context.Background(), func(ctx context.Context, url string) ([]byte, int, error) {
		return []byte(`[]`), 200, nil
	}, "example.com")
	if row.Status != checker.StatusNotFound || !strings.Contains(row.Evidence, "crt.sh") {
		t.Fatalf("%+v", row)
	}
}

func TestCertificatesRateLimit(t *testing.T) {
	row := Certificates(context.Background(), func(ctx context.Context, url string) ([]byte, int, error) {
		return []byte("slow down"), 429, nil
	}, "example.com")
	if row.Status != checker.StatusRateLimited || row.Evidence != "" {
		t.Fatalf("%+v", row)
	}
}
