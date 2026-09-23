package profiles

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

func get(ctx context.Context, c *http.Client, rawURL string) (int, http.Header, []byte, error) {
	return getAccept(ctx, c, rawURL, "application/json, text/html;q=0.9")
}

func getAccept(ctx context.Context, c *http.Client, rawURL, accept string) (int, http.Header, []byte, error) {
	if c == nil {
		return 0, nil, nil, errors.New("nil client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Accept", accept)
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

func limited(status int, body []byte) bool {
	return httpx.IsLimited(status, body)
}

func finishLimited() (checker.Status, string) {
	return checker.StatusRateLimited, "rate limited"
}

func unexpected() (checker.Status, string) {
	return checker.StatusError, "unexpected response"
}

func profileResult(name, domain, category, profile string, status checker.Status, detail string, elapsed time.Duration) checker.Result {
	res := checker.Result{
		Site:     name,
		Domain:   domain,
		Category: category,
		Method:   "profile",
		Status:   status,
		Detail:   oneLine(detail),
		Duration: elapsed,
	}
	switch status {
	case checker.StatusFound:
		res.ProfileURL = profile
		res.Evidence = "Public profile exists for this username."
	case checker.StatusNotFound:
		res.Evidence = "No public profile exists for this username."
	}
	return res
}

func profileURL(raw, username string) string {
	return raw + url.PathEscape(username)
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(stripTags(s)), " ")
	if len(s) > 80 {
		return s[:79] + "…"
	}
	return s
}

func stripTags(s string) string {
	var b strings.Builder
	for {
		start := strings.IndexByte(s, '<')
		if start < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:start])
		end := strings.IndexByte(s[start:], '>')
		if end < 0 {
			break
		}
		s = s[start+end+1:]
	}
	return b.String()
}
