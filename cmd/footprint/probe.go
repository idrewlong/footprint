package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"time"

	"github.com/idrewlong/footprint/internal/httpx"
	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/sites"
)

// probeBodyLimit is how much of each response body the probe keeps.
// Site checks already stop at 1 MiB; the probe matches that and says so
// when the server sent more.
const probeBodyLimit = 1 << 20

func runProbe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		allowNotify bool
		proxyURL    string
		timeout     time.Duration
	)
	fs.BoolVar(&allowNotify, "allow-notify", false, "allow a password-reset check, which can email the address")
	fs.StringVar(&proxyURL, "proxy", "", "route the check through a proxy (http, https, socks5, socks5h)")
	fs.DurationVar(&timeout, "timeout", checker.DefaultTimeout, "check timeout")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"allow-notify": true,
		"h":            true,
		"help":         true,
	}, map[string]bool{
		"proxy":   true,
		"timeout": true,
	})
	if splitErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", splitErr)
		return 2
	}
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positionals) != 2 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if timeout <= 0 {
		fmt.Fprintln(stderr, "footprint: --timeout must be greater than 0")
		return 2
	}
	email, ok := normalizeEmail(positionals[1])
	if !ok {
		fmt.Fprintln(stderr, "footprint: email address is not valid")
		return 2
	}
	selected, err := sites.Select(nil, []string{positionals[0]})
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 2
	}
	site := selected[0]
	if msg := notifyBlocked(site, email, allowNotify); msg != "" {
		fmt.Fprintf(stderr, "footprint: %s\n", msg)
		return 2
	}
	transport, proxyErr := proxyTransport(proxyURL)
	if proxyErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", proxyErr)
		return 2
	}
	defer transport.CloseIdleConnections()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, exchanges := probeSite(ctx, site, email, transport, timeout)
	if err := writeProbe(stdout, site, email, res, exchanges); err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	return 0
}

// notifyBlocked refuses a password-reset check unless the operator opted in.
// Those checks can email the address.
func notifyBlocked(site checker.Site, email string, allowNotify bool) string {
	if checker.Notifies(site.Method()) && !allowNotify {
		return fmt.Sprintf("%s uses %s and can email %s; pass --allow-notify to run it", site.Name(), site.Method(), email)
	}
	return ""
}

// probeSite runs one check on the same client a scan uses, and records
// every request that client sent and the response the server returned
// before any challenge rewrite.
func probeSite(ctx context.Context, site checker.Site, email string, transport http.RoundTripper, timeout time.Duration) (checker.Result, []exchange) {
	rec := &recordingTransport{base: transport}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := httpx.NewClient(httpx.Config{
		Timeout:   timeout,
		Gate:      httpx.NewGate(time.Minute),
		Transport: rec,
	})
	start := time.Now()
	res := site.Check(ctx, client, email)
	if res.Duration == 0 {
		res.Duration = time.Since(start)
	}
	if res.Site == "" {
		res.Site = site.Name()
	}
	if res.Status == "" {
		res.Status = checker.StatusError
		if res.Detail == "" {
			res.Detail = "empty result"
		}
	}
	return res, rec.snapshot()
}

type exchange struct {
	method     string
	url        string
	reqHeader  http.Header
	status     string
	statusCode int
	respHeader http.Header
	body       []byte
	truncated  bool
	err        error
}

// recordingTransport sits under the shared client so it sees the headers
// the client actually sent and the body the server actually returned.
type recordingTransport struct {
	base http.RoundTripper
	mu   sync.Mutex
	got  []exchange
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	ex := exchange{
		method:    req.Method,
		url:       req.URL.String(),
		reqHeader: req.Header.Clone(),
	}
	if err != nil {
		ex.err = err
		t.record(ex)
		return nil, err
	}
	ex.status = resp.Status
	ex.statusCode = resp.StatusCode
	if resp.Header != nil {
		ex.respHeader = resp.Header.Clone()
	}
	if resp.Body != nil {
		buf, readErr := io.ReadAll(io.LimitReader(resp.Body, probeBodyLimit))
		extra := make([]byte, 1)
		n, _ := resp.Body.Read(extra)
		ex.truncated = n > 0
		ex.body = bytes.Clone(buf)
		if readErr != nil {
			ex.err = readErr
		}
		tail := io.Reader(resp.Body)
		if n > 0 {
			tail = io.MultiReader(bytes.NewReader(extra[:n]), resp.Body)
		}
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), tail), resp.Body}
	}
	t.record(ex)
	return resp, nil
}

func (t *recordingTransport) record(ex exchange) {
	t.mu.Lock()
	t.got = append(t.got, ex)
	t.mu.Unlock()
}

func (t *recordingTransport) snapshot() []exchange {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]exchange(nil), t.got...)
}

func writeProbe(w io.Writer, site checker.Site, email string, res checker.Result, exchanges []exchange) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "site: %s\n", site.Name())
	fmt.Fprintf(&buf, "domain: %s\n", site.Domain())
	fmt.Fprintf(&buf, "method: %s\n", site.Method())
	fmt.Fprintf(&buf, "email: %s\n", email)
	fmt.Fprintf(&buf, "status: %s\n", res.Status)
	if res.Detail != "" {
		fmt.Fprintf(&buf, "detail: %s\n", res.Detail)
	}
	if res.Evidence != "" {
		fmt.Fprintf(&buf, "evidence: %s\n", res.Evidence)
	}
	fmt.Fprintf(&buf, "duration: %s\n", res.Duration.Round(time.Millisecond))
	if len(exchanges) == 0 {
		fmt.Fprintf(&buf, "\nno request left the client\n")
	}
	for i, ex := range exchanges {
		fmt.Fprintf(&buf, "\n--- %d. %s %s\n", i+1, ex.method, ex.url)
		writeHeaders(&buf, "> ", ex.reqHeader)
		if ex.err != nil && ex.statusCode == 0 {
			fmt.Fprintf(&buf, "error: %s\n", ex.err)
			continue
		}
		status := ex.status
		if status == "" {
			status = fmt.Sprintf("%d", ex.statusCode)
		}
		fmt.Fprintf(&buf, "< %s\n", status)
		writeHeaders(&buf, "< ", ex.respHeader)
		fmt.Fprintln(&buf)
		buf.Write(ex.body)
		if len(ex.body) == 0 || ex.body[len(ex.body)-1] != '\n' {
			fmt.Fprintln(&buf)
		}
		if ex.truncated {
			fmt.Fprintf(&buf, "(truncated at %d bytes)\n", probeBodyLimit)
		}
		if ex.err != nil {
			fmt.Fprintf(&buf, "error: %s\n", ex.err)
		}
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func writeHeaders(buf *bytes.Buffer, prefix string, header http.Header) {
	if len(header) == 0 {
		return
	}
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range header[key] {
			fmt.Fprintf(buf, "%s%s: %s\n", prefix, key, value)
		}
	}
}
