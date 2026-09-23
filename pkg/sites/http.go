package sites

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/idrewlong/footprint/internal/httpx"
	"github.com/idrewlong/footprint/pkg/checker"
)

// base is the metadata shared by every site file.
type base struct {
	name, domain, category, method string
	deleteURL, securityURL         string
}

func (b base) Name() string     { return b.name }
func (b base) Domain() string   { return b.domain }
func (b base) Category() string { return b.category }
func (b base) Method() string   { return b.method }

func (b base) result(status checker.Status, detail string, elapsed time.Duration) checker.Result {
	res := checker.Result{
		Site:     b.name,
		Domain:   b.domain,
		Category: b.category,
		Method:   b.method,
		Status:   status,
		Detail:   detail,
		Duration: elapsed,
	}
	if status == checker.StatusFound {
		res.DeleteURL = b.deleteURL
		res.SecurityURL = b.securityURL
	}
	return res
}

func do(ctx context.Context, c *http.Client, req *http.Request) (int, http.Header, []byte, error) {
	if c == nil {
		return 0, nil, nil, errors.New("nil client")
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, body, err
}

func fromErr(err error) (checker.Status, string) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		if errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return checker.StatusError, "cancelled"
		}
		return checker.StatusError, "timed out"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return checker.StatusError, "timed out"
	}
	return checker.StatusError, "request failed"
}

func get(ctx context.Context, c *http.Client, rawURL string, header http.Header) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	copyHeader(req.Header, header)
	return do(ctx, c, req)
}

func postForm(ctx context.Context, c *http.Client, rawURL string, form url.Values, header http.Header) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	copyHeader(req.Header, header)
	return do(ctx, c, req)
}

func postJSON(ctx context.Context, c *http.Client, rawURL string, payload []byte, header http.Header) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(string(payload)))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	copyHeader(req.Header, header)
	return do(ctx, c, req)
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Set(key, value)
		}
	}
}

func limited(status int, body []byte) bool {
	return httpx.IsLimited(status, body)
}

func finishLimited() (checker.Status, string) {
	return checker.StatusRateLimited, "rate limited"
}

func unexpected() (checker.Status, string) {
	return checker.StatusError, "unexpected response"
}
