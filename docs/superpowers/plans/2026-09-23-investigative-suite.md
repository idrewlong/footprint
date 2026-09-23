# Investigative suite implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add local domain, IP, and entity lookups, saved case files, and diff, then stop for a local test gate before any MCP server.

**Architecture:** New packages return `[]checker.Result` and `pkg/report` renders them with the existing case note. DNS, HTTP, GeoIP, and the sanctions file are interfaces, so unit tests never touch the network. `cmd/footprint-mcp` is specified in the last phase and is not started until the local gate passes and the user says to continue.

**Tech Stack:** Go 1.27 (the version in `go.mod`). Standard library for DNS, HTTP, CSV, and JSON. One new dependency, `github.com/oschwald/maxminddb-golang`, only for reading a GeoIP database the user already has.

**Spec:** `docs/superpowers/specs/2026-09-23-investigative-suite-design.md`

## Global Constraints

- Statuses are only `found`, `not_found`, `rate_limited`, and `error`. An unknown outcome is never `not_found`.
- Methods added here are `dns`, `infra`, and `entity`. Existing methods stay `register`, `login`, `password_reset`, `breach`, and `profile`.
- Do not log in, submit a password, or return breach contents.
- Do not add a people-search, household lookup, tax-record lookup, or property-roll lookup.
- Do not print latitude or longitude.
- The mailbox local-part is never sent. A private IP is never sent to Team Cymru or RDAP.
- Fixture and unit tests must not open network connections. `go test ./...` stays offline.
- CLI data goes to stdout. Diagnostics, save paths, and the suggested username command go to stderr. Usage errors exit 2. A report that failed to write exits 1. A finished report exits 0 even when rows are `error`.
- Saved report files are mode `0600`. Created directories are mode `0700`.
- Match the comment and error-wrapping style already in `pkg/checker` and `cmd/footprint`.

## Review Focus

These are pinned by the tasks below. Do not weaken them.

- A DNS timeout must stay `error` with empty evidence. Task 1.
- A missing GeoIP file must not invent a city. Task 4.
- A missing OFAC file must not say the name is clear. Task 5.
- A later `rate_limited` or missing row must be Unchecked, not Gone. Task 3.
- GeoIP evidence must say it is the network's city, not a person or a street address, and must not contain coordinates. Task 4.
- `10.1.1.1` must not call ASN TXT lookup or RDAP. Task 4.
- `lookup entity someone@example.com` and `lookup entity 8.8.8.8` exit 2. Task 6.
- `--save` files are mode `0600`. Task 3.
- `lookup domain ada@example.com` looks up `example.com` only. Task 1.

## File map

| Path | Responsibility |
|---|---|
| `pkg/domain/domain.go` | Strip a mailbox, query MX, SPF, DMARC, disposable list |
| `pkg/domain/certs.go` | Opt-in crt.sh count |
| `pkg/domain/disposable.go` | Local disposable-domain set |
| `pkg/infra/infra.go` | PTR, ASN, GeoIP, RDAP |
| `pkg/infra/maxmind.go` | Open a local GeoLite2 City database |
| `pkg/entity/entity.go` | Exact OFAC match and SEC ticker match |
| `pkg/casefile/casefile.go` | Save, load, diff, merge |
| `pkg/report/report.go` | Sections for `dns`, `infra`, and `entity` |
| `cmd/footprint/cli.go` | `lookup`, `diff`, `note`, `--save` |
| `cmd/footprint-mcp/` | Phase 2 only, after the gate |

## Phase 1 — local workstation

Do tasks 1 through 7 in order. Stop at Task 7. Do not start Phase 2 in the same pass.

### Task 1: Domain lookup

**Files:**
- Create: `pkg/domain/domain.go`
- Create: `pkg/domain/domain_test.go`
- Create: `pkg/domain/disposable.go`
- Modify: `pkg/checker/checker.go` (method comment only)

**Interfaces:**
- Consumes: `checker.Result`, `checker.StatusFound`, `checker.StatusNotFound`, `checker.StatusError`
- Produces:
  - `func Host(query string) (string, error)`
  - `type Resolver interface { LookupMX(ctx context.Context, name string) ([]*net.MX, error); LookupTXT(ctx context.Context, name string) ([]string, error) }`
  - `func Check(ctx context.Context, r Resolver, query string, disposable map[string]struct{}) ([]checker.Result, error)`
  - `func BuiltinDisposable() map[string]struct{}`

- [ ] **Step 1: Write the failing test**

Create `pkg/domain/domain_test.go`:

```go
package domain

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/idrewlong/footprint/pkg/checker"
)

type fakeDNS struct {
	mx    []*net.MX
	mxErr error
	txt   map[string][]string
	txtErr map[string]error
	seen  []string
}

func (f *fakeDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	f.seen = append(f.seen, "MX "+name)
	return f.mx, f.mxErr
}

func (f *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.seen = append(f.seen, "TXT "+name)
	if err := f.txtErr[name]; err != nil {
		return nil, err
	}
	return f.txt[name], nil
}

func TestHostStripsMailbox(t *testing.T) {
	host, err := Host("Ada@Example.com")
	if err != nil || host != "example.com" {
		t.Fatalf("host %q err %v", host, err)
	}
}

func TestCheckDoesNotSendLocalPart(t *testing.T) {
	dns := &fakeDNS{
		mx: []*net.MX{{Host: "mx.example.com.", Pref: 10}},
		txt: map[string][]string{
			"example.com":       {"v=spf1 mx -all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject"},
		},
	}
	rows, err := Check(context.Background(), dns, "ada@example.com", BuiltinDisposable())
	if err != nil {
		t.Fatal(err)
	}
	for _, seen := range dns.seen {
		if strings.Contains(seen, "ada") {
			t.Fatalf("local-part was sent: %s", seen)
		}
	}
	if len(rows) != 4 {
		t.Fatalf("rows %d", len(rows))
	}
}

func TestDNSTimeoutIsError(t *testing.T) {
	dns := &fakeDNS{mxErr: &net.DNSError{Err: "timeout", IsTimeout: true, Name: "example.com"}}
	rows, err := Check(context.Background(), dns, "example.com", BuiltinDisposable())
	if err != nil {
		t.Fatal(err)
	}
	mx := rowBySite(rows, "mx")
	if mx.Status != checker.StatusError || mx.Evidence != "" {
		t.Fatalf("mx status %s evidence %q", mx.Status, mx.Evidence)
	}
}

func TestNoMXIsNotFound(t *testing.T) {
	dns := &fakeDNS{mxErr: &net.DNSError{Err: "no such host", IsNotFound: true, Name: "example.com"}}
	rows, err := Check(context.Background(), dns, "example.com", map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	mx := rowBySite(rows, "mx")
	if mx.Status != checker.StatusNotFound || mx.Evidence == "" {
		t.Fatalf("mx %+v", mx)
	}
}

func TestDisposableHit(t *testing.T) {
	dns := &fakeDNS{txt: map[string][]string{}}
	rows, err := Check(context.Background(), dns, "mailinator.com", BuiltinDisposable())
	if err != nil {
		t.Fatal(err)
	}
	row := rowBySite(rows, "disposable")
	if row.Status != checker.StatusFound || row.Method != "dns" {
		t.Fatalf("%+v", row)
	}
}

func TestNilDisposableListIsError(t *testing.T) {
	dns := &fakeDNS{}
	rows, err := Check(context.Background(), dns, "example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	row := rowBySite(rows, "disposable")
	if row.Status != checker.StatusError || row.Evidence != "" {
		t.Fatalf("%+v", row)
	}
}

func TestSPFRecordIsFound(t *testing.T) {
	dns := &fakeDNS{txt: map[string][]string{"example.com": {"v=spf1 -all"}}}
	rows, err := Check(context.Background(), dns, "example.com", map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	spf := rowBySite(rows, "spf")
	if spf.Status != checker.StatusFound || !strings.Contains(spf.Evidence, "v=spf1") {
		t.Fatalf("%+v", spf)
	}
}

func rowBySite(rows []checker.Result, site string) checker.Result {
	for _, row := range rows {
		if row.Site == site {
			return row
		}
	}
	return checker.Result{}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./pkg/domain/ -count=1`

Expected: FAIL because package `domain` does not exist, or `Host` is undefined.

- [ ] **Step 3: Implement domain lookup**

`pkg/checker/checker.go` method comment becomes: `register`, `login`, `password_reset`, `breach`, `profile`, `dns`, `infra`, or `entity`.

`pkg/domain/disposable.go` returns a map containing at least: `mailinator.com`, `guerrillamail.com`, `yopmail.com`, `tempmail.com`, `10minutemail.com`, `trashmail.com`, `getnada.com`, `dispostable.com`, `sharklasers.com`, `maildrop.cc`. Keys are lowercase.

`pkg/domain/domain.go`:

```go
package domain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"

	"github.com/idrewlong/footprint/pkg/checker"
)

// Resolver is the DNS surface Check needs. Tests supply a fake.
type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Host returns the domain. A mailbox keeps only the part after @.
func Host(query string) (string, error) {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" || strings.ContainsAny(query, " /\\") {
		return "", fmt.Errorf("domain is not valid")
	}
	if strings.Contains(query, "@") {
		addr, err := mail.ParseAddress(query)
		if err != nil {
			return "", fmt.Errorf("email address is not valid")
		}
		_, host, ok := strings.Cut(addr.Address, "@")
		if !ok || host == "" || strings.Contains(host, "@") {
			return "", fmt.Errorf("email address is not valid")
		}
		return host, nil
	}
	return query, nil
}

// Check reports MX, SPF, DMARC, and the local disposable list.
// disposable == nil is an error row, not a miss.
func Check(ctx context.Context, r Resolver, query string, disposable map[string]struct{}) ([]checker.Result, error) {
	host, err := Host(query)
	if err != nil {
		return nil, err
	}
	return []checker.Result{
		checkMX(ctx, r, host),
		checkMarker(ctx, r, host, host, "spf", "v=spf1", "SPF"),
		checkMarker(ctx, r, "_dmarc."+host, host, "dmarc", "v=DMARC1", "DMARC"),
		checkDisposable(host, disposable),
	}, nil
}

func checkMX(ctx context.Context, r Resolver, host string) checker.Result {
	base := checker.Result{Site: "mx", Domain: host, Category: "domain", Method: "dns"}
	mx, err := r.LookupMX(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			base.Status = checker.StatusNotFound
			base.Evidence = "DNS said this name has no MX records."
			return base
		}
		base.Status = checker.StatusError
		base.Detail = "dns lookup failed"
		return base
	}
	if len(mx) == 0 {
		base.Status = checker.StatusNotFound
		base.Evidence = "DNS returned no MX records."
		return base
	}
	base.Status = checker.StatusFound
	base.Evidence = "MX records point at " + strings.TrimSuffix(mx[0].Host, ".") + "."
	return base
}

func checkMarker(ctx context.Context, r Resolver, lookupName, host, site, prefix, label string) checker.Result {
	base := checker.Result{Site: site, Domain: host, Category: "domain", Method: "dns"}
	txt, err := r.LookupTXT(ctx, lookupName)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			base.Status = checker.StatusNotFound
			base.Evidence = "DNS returned no " + label + " record."
			return base
		}
		base.Status = checker.StatusError
		base.Detail = "dns lookup failed"
		return base
	}
	for _, rec := range txt {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), strings.ToLower(prefix)) {
			base.Status = checker.StatusFound
			base.Evidence = label + " record is " + oneLine(rec) + "."
			return base
		}
	}
	base.Status = checker.StatusNotFound
	base.Evidence = "DNS returned no " + label + " record."
	return base
}

func checkDisposable(host string, list map[string]struct{}) checker.Result {
	base := checker.Result{Site: "disposable", Domain: host, Category: "domain", Method: "dns"}
	if list == nil {
		base.Status = checker.StatusError
		base.Detail = "disposable list not configured"
		return base
	}
	if _, ok := list[host]; ok {
		base.Status = checker.StatusFound
		base.Evidence = "Local disposable-domain list includes " + host + "."
		return base
	}
	base.Status = checker.StatusNotFound
	base.Evidence = "Local disposable-domain list does not include " + host + "."
	return base
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
```

`oneLine` collapses whitespace so a TXT record cannot break the case note. `checkMarker` stores the mailbox domain in `Domain` and uses `lookupName` only for the query, so DMARC evidence stays on `example.com` while the lookup hits `_dmarc.example.com`.

- [ ] **Step 4: Run the test**

Run: `go test ./pkg/domain/ -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/domain pkg/checker/checker.go
git commit -m "$(cat <<'EOF'
Add a local DNS check for mailbox domains.

MX, SPF, DMARC, and the disposable list record the DNS answer, and a timeout stays an error.
EOF
)"
```

### Task 2: Opt-in certificate count

**Files:**
- Create: `pkg/domain/certs.go`
- Create: `pkg/domain/certs_test.go`

**Interfaces:**
- Consumes: `checker.Result`
- Produces: `func Certificates(ctx context.Context, get func(context.Context, string) ([]byte, int, error), domain string) checker.Result`

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./pkg/domain/ -run Certificates -count=1`

Expected: FAIL with `undefined: Certificates`

- [ ] **Step 3: Implement certificate count**

Request `https://crt.sh/?q=<domain>&output=json` using `url.Values`, so the domain is a query parameter and is not prefixed with `%`. Parse a JSON array of objects with `common_name`. Unique the names, sort them, and put at most 20 in `Detail`. Evidence: `crt.sh lists N certificates for this domain.` Status 429 is `rate_limited`. A non-200 status, invalid JSON, or a transport error is `error` with empty evidence. An empty array is `not_found` with evidence `crt.sh lists no certificates for this domain.`

`Check` does not call `Certificates`. The CLI calls it only with `--certs`.

- [ ] **Step 4: Run the test**

Run: `go test ./pkg/domain/ -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/domain/certs.go pkg/domain/certs_test.go
git commit -m "$(cat <<'EOF'
Add an opt-in certificate count from crt.sh.

The domain lookup stays on DNS unless the caller asks for certificates.
EOF
)"
```

### Task 3: Case files and diff

**Files:**
- Create: `pkg/casefile/casefile.go`
- Create: `pkg/casefile/casefile_test.go`

**Interfaces:**
- Consumes: `report.Document`, `checker.Result`
- Produces:
  - `type Saved struct { Version string \`json:"version"\`; RanAt time.Time \`json:"ran_at"\`; ElapsedMS int64 \`json:"elapsed_ms"\`; Kind string \`json:"kind"\`; Report report.Document \`json:"report"\` }`
  - `func DefaultDir() (string, error)`
  - `func Save(dir string, saved Saved) (string, error)`
  - `func Load(path string) (Saved, error)`
  - `type Delta struct { Added, Gone, Unchecked, Still []checker.Result }`
  - `func Diff(old, new report.Document) Delta`
  - `func WriteDiff(w io.Writer, d Delta) error`
  - `func Merge(docs ...report.Document) (report.Document, error)`

- [ ] **Step 1: Write the failing test**

Cover all of the following in `pkg/casefile/casefile_test.go`.

Save a document into `t.TempDir()` and assert `info.Mode().Perm() == 0o600`. Assert the parent directory created by `Save` is `0o700` when it does not already exist. `Load` returns the same email and the same first evidence sentence.

`Diff` with these rows:

| Site | Old status | New status | Bucket |
|---|---|---|---|
| adobe | found | found | Still |
| github | not_found | found | Added |
| slack | found | not_found | Gone |
| zoom | found | rate_limited | Unchecked |
| dropbox | found | absent | Unchecked |

`Merge` of an email report and a domain report keeps both subject fields and re-summarizes from the concatenated rows. `Merge` of two email reports with different addresses returns an error.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./pkg/casefile/ -count=1`

Expected: FAIL with package not found or undefined `Save`.

- [ ] **Step 3: Implement case files**

`DefaultDir` joins the user home directory with `.local/share/footprint`.

`Save` creates `dir` with `os.MkdirAll(dir, 0o700)`, writes via `os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)`, and encodes `Saved` with `json.Encoder` and `SetEscapeHTML(false)`. The file name is `20060102T150405.000000000Z-<kind>-<slug>.json` using `saved.RanAt` in UTC. Slug comes from the first set subject (email, username, domain, IP, entity), lowercased, with every rune outside `a-z`, `0-9`, `.`, and `-` replaced by `_`.

`Diff` keys rows by `method + "\x00" + site`. A new `found` whose old row is missing or `not_found` is Added. An old `found` whose new row is `not_found` is Gone. An old `found` whose new row is missing, `rate_limited`, `error`, or any other non-found status is Unchecked. Both `found` is Still. Do not put Unchecked rows into Gone.

`WriteDiff` prints four sections in that order: Added, Gone, Unchecked, Still. Each changed row is `- site (method): evidence` or the status name when evidence is empty. Still prints the count only.

`Merge` copies subject fields. If both documents set the same subject to different non-empty values, return an error. Summary is `report.Summarize` of the concatenated results, not the sum of the stored summaries.

Add these fields to `report.Document` before `Merge` can compile:

```go
SubjectDomain string `json:"subject_domain,omitempty"`
SubjectIP     string `json:"subject_ip,omitempty"`
SubjectEntity string `json:"subject_entity,omitempty"`
```

Existing JSON without those keys still unmarshals.

- [ ] **Step 4: Run the test**

Run: `go test ./pkg/casefile/ ./pkg/report/ -count=1`

Expected: PASS. Existing report tests still pass.

- [ ] **Step 5: Commit**

```bash
git add pkg/casefile pkg/report/report.go
git commit -m "$(cat <<'EOF'
Save local case files and diff them without treating a blocked re-check as a deletion.

Reports are mode 0600, and a rate-limited follow-up stays unchecked.
EOF
)"
```

### Task 4: IP lookup

**Files:**
- Create: `pkg/infra/infra.go`
- Create: `pkg/infra/infra_test.go`
- Create: `pkg/infra/maxmind.go`
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: `checker.Result`
- Produces:
  - `type Resolver interface { LookupAddr(ctx context.Context, addr string) ([]string, error); LookupTXT(ctx context.Context, name string) ([]string, error) }`
  - `type Place struct { City, Region, Country string }`
  - `type GeoIP interface { Lookup(ip net.IP) (Place, error) }`
  - `type Fetcher interface { Get(ctx context.Context, url string) ([]byte, int, error) }`
  - `func Check(ctx context.Context, r Resolver, geo GeoIP, fetch Fetcher, ip string) ([]checker.Result, error)`
  - `func OpenGeoIP(path string) (GeoIP, error)`

- [ ] **Step 1: Write the failing test**

```go
func TestPrivateIPIsNotSent(t *testing.T) {
	dns := &fakeInfra{}
	fetch := &fakeFetch{}
	rows, err := Check(context.Background(), dns, fakeGeo{}, fetch, "10.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(dns.txt) != 0 || fetch.called {
		t.Fatal("private address was sent")
	}
	for _, site := range []string{"asn", "geoip", "rdap"} {
		row := rowBySite(rows, site)
		if row.Status != checker.StatusError || row.Evidence != "" {
			t.Fatalf("%s %+v", site, row)
		}
	}
}

func TestASNEvidenceNamesTeamCymru(t *testing.T) {
	dns := &fakeInfra{txt: map[string][]string{
		"4.3.2.1.origin.asn.cymru.com": {"15169 | 1.2.3.4/24 | US | arin | 2000-03-30"},
	}}
	rows, err := Check(context.Background(), dns, nil, nil, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	asn := rowBySite(rows, "asn")
	if asn.Status != checker.StatusFound || !strings.Contains(asn.Evidence, "Team Cymru") || !strings.Contains(asn.Evidence, "AS15169") {
		t.Fatalf("%+v", asn)
	}
}

func TestMissingGeoIPIsError(t *testing.T) {
	rows, err := Check(context.Background(), &fakeInfra{}, nil, nil, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	row := rowBySite(rows, "geoip")
	if row.Status != checker.StatusError || row.Evidence != "" || strings.Contains(strings.ToLower(row.Detail), "city") {
		t.Fatalf("%+v", row)
	}
}

func TestGeoIPSentence(t *testing.T) {
	rows, err := Check(context.Background(), &fakeInfra{}, fakeGeo{place: Place{City: "Ashburn", Region: "Virginia", Country: "US"}}, nil, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	row := rowBySite(rows, "geoip")
	if row.Status != checker.StatusFound {
		t.Fatalf("%+v", row)
	}
	if !strings.Contains(row.Evidence, "Ashburn") || !strings.Contains(row.Evidence, "not a person or a street address") {
		t.Fatalf("%+v", row)
	}
	if strings.Contains(row.Evidence, "°") || strings.Contains(row.Detail, "°") || strings.Contains(row.Evidence, "39.04") || strings.Contains(row.Detail, "39.04") {
		t.Fatalf("coordinates leaked: %+v", row)
	}
}

func TestRDAPNamesTheNetwork(t *testing.T) {
	fetch := &fakeFetch{status: 200, body: []byte(`{"handle":"NET-8-8-8-0-1","name":"GOOGLE"}`)}
	rows, err := Check(context.Background(), &fakeInfra{}, nil, fetch, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	row := rowBySite(rows, "rdap")
	if row.Status != checker.StatusFound || !strings.Contains(row.Evidence, "GOOGLE") || !strings.Contains(row.Evidence, "RDAP") {
		t.Fatalf("%+v", row)
	}
}

func TestOpenGeoIPMissingFile(t *testing.T) {
	_, err := OpenGeoIP(filepath.Join(t.TempDir(), "missing.mmdb"))
	if err == nil {
		t.Fatal("expected error")
	}
}
```

`fakeInfra` records every `LookupTXT` name in `txt` calls and does not invent records. `fakeFetch` records whether `Get` was called. `fakeGeo` returns its `place` field.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./pkg/infra/ -count=1`

Expected: FAIL with undefined `Check`.

- [ ] **Step 3: Implement IP lookup**

`Check` parses with `net.ParseIP`. An unparseable string returns an error, so the CLI can exit 2. It always appends four rows, sites `ptr`, `asn`, `geoip`, and `rdap`, method `infra`, category `infra`.

`public` is false for nil, `IsPrivate`, `IsLoopback`, `IsLinkLocalUnicast`, `IsUnspecified`, `IsMulticast`, `100.64.0.0/10`, and `2001:db8::/32`. For a non-public address, still call `LookupAddr`. Do not call `LookupTXT` or `Fetcher.Get`. The asn, geoip, and rdap rows are `error`, detail `private address is not sent to a public lookup`, evidence empty.

PTR: `LookupAddr`. `IsNotFound` is `not_found` with evidence `Reverse DNS has no name for this address.` Other errors are `error` with empty evidence. Names are trimmed of a trailing dot. Evidence: `Reverse DNS names this address <host>.`

ASN lookup name for IPv4 `a.b.c.d` is `d.c.b.a.origin.asn.cymru.com`. Parse the first pipe field as the ASN. Evidence: `Team Cymru DNS lists AS<asn> for this address. The registry country is the network's country, not a person's location.` A timeout or bad payload is `error` with empty evidence.

GeoIP: a nil `GeoIP` produces `error`, detail `geoip database not configured`, evidence empty. A successful `Place` produces evidence `GeoIP database places this address in <city, region, country>. This is the network's city, not a person or a street address.` Omit empty place parts. Do not add latitude or longitude fields.

RDAP: a nil `Fetcher` produces `error`, detail `rdap client not configured`. Otherwise GET `https://rdap.org/ip/<ip>` with the IP in the path unescaped. 200 with a non-empty `name` is `found`. Evidence: `RDAP lists network <name> (<handle>). This is the registered network, not a person.` 404 is `not_found`. 429 is `rate_limited`. Anything else, including 200 with an empty name, is `error` with empty evidence.

`OpenGeoIP` uses `github.com/oschwald/maxminddb-golang` v1 (`maxminddb.Open`). Run `go get github.com/oschwald/maxminddb-golang@v1`. If that module path fails, stop and report the error. Do not guess a replacement. Map the English city name, the first subdivision's English name, and the country ISO code into `Place`. A missing file returns the open error.

- [ ] **Step 4: Run the test**

Run: `go test ./pkg/infra/ -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/infra go.mod go.sum
git commit -m "$(cat <<'EOF'
Look up a public IP as a network, not a person.

Private addresses stay on the local resolver, and a missing GeoIP database stays an error.
EOF
)"
```

### Task 5: Entity lookup

**Files:**
- Create: `pkg/entity/entity.go`
- Create: `pkg/entity/entity_test.go`

**Interfaces:**
- Consumes: `checker.Result`
- Produces:
  - `func Validate(name string) error`
  - `type Record struct { Name, Type, Program string }`
  - `func LoadSDN(r io.Reader) ([]Record, error)`
  - `func Screen(name string, records []Record) checker.Result`
  - `type Ticker struct { CIK int; Ticker, Title string }`
  - `func ParseTickers(r io.Reader) ([]Ticker, error)`
  - `func MatchTickers(name string, tickers []Ticker) checker.Result`
  - `type Fetcher interface { Get(ctx context.Context, url string) ([]byte, int, error) }`
  - `func SEC(ctx context.Context, fetch Fetcher, name string) checker.Result`

- [ ] **Step 1: Write the failing test**

```go
func TestValidateRejectsEmailAndIP(t *testing.T) {
	if Validate("someone@example.com") == nil || Validate("8.8.8.8") == nil {
		t.Fatal("expected usage errors")
	}
	if err := Validate("Apple Inc."); err != nil {
		t.Fatal(err)
	}
}

func TestScreenExactOnly(t *testing.T) {
	records := []Record{{Name: "Example Corp", Type: "Entity", Program: "SDGT"}}
	hit := Screen("example corp", records)
	if hit.Status != checker.StatusFound || !strings.Contains(hit.Evidence, "OFAC") || !strings.Contains(hit.Evidence, "SDGT") {
		t.Fatalf("%+v", hit)
	}
	partial := Screen("example", records)
	if partial.Status != checker.StatusNotFound {
		t.Fatalf("partial %+v", partial)
	}
}

func TestScreenMissingList(t *testing.T) {
	row := Screen("Example Corp", nil)
	if row.Status != checker.StatusError || row.Evidence != "" {
		t.Fatalf("%+v", row)
	}
}

func TestLoadSDNHeaderless(t *testing.T) {
	in := "123,Example Corp,Entity,SDGT,,,,,,,,,,\n"
	records, err := LoadSDN(strings.NewReader(in))
	if err != nil || len(records) != 1 || records[0].Name != "Example Corp" || records[0].Program != "SDGT" {
		t.Fatalf("%v %+v", err, records)
	}
}

func TestMatchTickerExact(t *testing.T) {
	tickers := []Ticker{{CIK: 320193, Ticker: "AAPL", Title: "Apple Inc."}}
	hit := MatchTickers("aapl", tickers)
	if hit.Status != checker.StatusFound || !strings.Contains(hit.Evidence, "320193") || !strings.Contains(hit.Evidence, "SEC") {
		t.Fatalf("%+v", hit)
	}
	miss := MatchTickers("Apple", tickers)
	if miss.Status != checker.StatusNotFound {
		t.Fatalf("substring matched: %+v", miss)
	}
}

func TestSECUsesFixture(t *testing.T) {
	body := []byte(`{"0":{"cik_str":320193,"ticker":"AAPL","title":"Apple Inc."}}`)
	row := SEC(context.Background(), fetcher(body, 200), "Apple Inc.")
	if row.Status != checker.StatusFound || row.Method != "entity" {
		t.Fatalf("%+v", row)
	}
}

func TestSECFailureIsError(t *testing.T) {
	row := SEC(context.Background(), fetcher(nil, 503), "Apple Inc.")
	if row.Status != checker.StatusError || row.Evidence != "" {
		t.Fatalf("%+v", row)
	}
}

type staticFetch struct {
	body   []byte
	status int
}

func (s staticFetch) Get(ctx context.Context, url string) ([]byte, int, error) {
	return s.body, s.status, nil
}

func fetcher(body []byte, status int) Fetcher {
	return staticFetch{body: body, status: status}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./pkg/entity/ -count=1`

Expected: FAIL with undefined `Validate`.

- [ ] **Step 3: Implement entity lookup**

`Validate` rejects empty strings, any string `mail.ParseAddress` accepts, and any string `net.ParseIP` accepts.

`LoadSDN` reads CSV. If the first field of the first row is `ent_num`, use header names `SDN_Name`, `SDN_Type`, and `Program`. Otherwise treat columns as position 1 name, position 2 type, position 3 program (zero-based 1, 2, 3). Skip rows with an empty name.

`Screen` on a nil slice returns `error`, detail `sanctions list not configured`, evidence empty. Normalize by lowercasing and dropping every rune that is not a letter or digit, same rule as `report.normalizeName`. Match the full normalized name only. Evidence on a hit: `Local OFAC SDN list matches this name as <name>, program <program>.` A loaded list with no match is `not_found` with evidence `Local OFAC SDN list has no exact match for this name.`

`ParseTickers` accepts the SEC object map (`{"0":{"cik_str":1,"ticker":"AAPL","title":"Apple Inc."}}`). `MatchTickers` hits when the normalized query equals the normalized title or the ticker. `Apple` does not match `Apple Inc.`

`SEC` GETs `https://www.sec.gov/files/company_tickers.json`. The CLI fetcher sets `User-Agent` to `footprint/dev (local research)`. A transport error or non-200 is `error` with empty evidence. 429 is `rate_limited`. A parsed list uses `MatchTickers`.

Both results use method `entity` and category `entity`. Site is `ofac` or `sec`.

- [ ] **Step 4: Run the test**

Run: `go test ./pkg/entity/ -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/entity
git commit -m "$(cat <<'EOF'
Screen organization names against a local OFAC file and SEC tickers.

Matches are exact, and a missing sanctions file stays an error.
EOF
)"
```

### Task 6: CLI commands

**Files:**
- Modify: `cmd/footprint/cli.go`
- Modify: `cmd/footprint/cli_test.go`
- Modify: `README.md`

**Interfaces:**
- Consumes: `domain.Check`, `domain.Certificates`, `infra.Check`, `entity.Validate`, `entity.Screen`, `entity.SEC`, `casefile.Save`, `casefile.Load`, `casefile.Diff`, `casefile.Merge`, `report.WriteHuman`, `report.WriteJSON`, `report.WriteMarkdown`
- Produces: commands `lookup domain`, `lookup ip`, `lookup entity`, `diff`, `note`, and `--save` on scan and lookup

- [ ] **Step 1: Write the failing CLI tests**

Add tests in `cmd/footprint/cli_test.go` that call `execute` with fakes injected the same way `catalogFunc` is injected today. Add a `lookupFunc` parameter only on the new command path so existing scan tests keep calling `execute` unchanged. If that split is awkward, test exported helpers `runLookup`, `runDiff`, and `runNote` directly.

Assertions:

- `lookup domain ada@example.com` with a fake resolver records the lookup name `example.com` and not `ada`. Exit 0. Human stdout contains `mx` and the evidence sentence.
- `lookup domain ada@example.com --certs` calls the certificate getter. Without `--certs`, the getter is not called.
- `lookup ip 10.1.1.1` exits 0 and stdout contains `private address is not sent`. The fake TXT lookup and fake HTTP getter are not called.
- `lookup ip not-an-ip` exits 2.
- `lookup entity someone@example.com` exits 2. `lookup entity 8.8.8.8` exits 2.
- `lookup entity "Apple Inc."` with a fake SEC body and a temp SDN file exits 0 and stdout contains `SEC` and `OFAC`.
- `scan email me@example.com --save` with `FOOTPRINT_HOME` or an explicit dir argument writes one `0600` file. The path appears on stderr, not instead of the report on stdout. Prefer a `--case-dir` flag over an environment variable so tests do not depend on the home directory. `--case-dir` defaults to `casefile.DefaultDir()` when empty.
- `diff old.json new.json` prints `Unchecked` for a found-then-rate-limited site and does not print that site under `Gone`.
- `note a.json b.json --md` includes both an email finding and a domain finding.

- [ ] **Step 2: Run the new tests and confirm they fail**

Run: `go test ./cmd/footprint/ -count=1`

Expected: FAIL on the new command names or flags.

- [ ] **Step 3: Implement the commands**

Usage block gains:

```text
  footprint lookup domain <domain-or-email> [--certs] [--json|--md] [--save] [--case-dir path]
  footprint lookup ip <ip> [--geoip path] [--json|--md] [--save] [--case-dir path]
  footprint lookup entity <name> --sdn path [--json|--md] [--save] [--case-dir path]
  footprint diff <old.json> <new.json>
  footprint note <report.json>... [--json|--md]
```

Wire the standard-library resolver:

```go
type netDNS struct{ r *net.Resolver }

func (n netDNS) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return n.r.LookupMX(ctx, name)
}
func (n netDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return n.r.LookupTXT(ctx, name)
}
func (n netDNS) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return n.r.LookupAddr(ctx, addr)
}
```

HTTP fetcher for RDAP, crt.sh, and SEC uses `httpx.NewClient` when a timeout client already exists there. Otherwise use `http.Client` with the command timeout. Set the SEC User-Agent only on the SEC request. Pass `nil` GeoIP when `--geoip` is empty. Pass `nil` records to `entity.Screen` only when `--sdn` is omitted, which yields the configured error row. A path that does not open is `error` detail `sanctions list not configured`, not `not_found`.

Build `report.Document` with `report.Build("", rows, false)` and then set `SubjectDomain`, `SubjectIP`, or `SubjectEntity`. Do not set `Email` on a domain lookup, or MX hits will be described as email matches.

`--save` calls `casefile.Save`. Kind is `identity`, `domain`, `infra`, or `entity`. Print `saved <path>` on stderr.

`diff` loads two files and writes `casefile.WriteDiff` to stdout.

`note` loads each path, `Merge`s them, and renders with the existing writers. `--md` is the default for `note` when neither `--json` nor `--md` is set, because the merged product is the case note. `diff` stays plain text.

Update `README.md` usage with the same commands and one sentence each: domain DNS does not send the mailbox local-part, IP lookup describes a network, entity lookup is an exact public-list match.

- [ ] **Step 4: Run the tests**

Run: `go test ./cmd/footprint/ ./pkg/... -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/footprint README.md
git commit -m "$(cat <<'EOF'
Add lookup, diff, and note commands that stay on the local case file.

Domain, IP, and entity checks render through the same report as an email scan.
EOF
)"
```

### Task 7: Case note sections and the suggested username

**Files:**
- Modify: `pkg/report/report.go`
- Modify: `pkg/report/report_test.go`
- Modify: `cmd/footprint/cli.go`
- Modify: `cmd/footprint/cli_test.go`
- Modify: `AGENTS.md` layout table

**Interfaces:**
- Consumes: `report.Document.SubjectDomain`, `SubjectIP`, `SubjectEntity`, result methods `dns`, `infra`, `entity`
- Produces: markdown sections `Domain`, `Infrastructure`, and `Entity`, plus a stderr line `Next: footprint scan username <name>` when a scan found a profile URL and the user did not pass a username

- [ ] **Step 1: Write the failing tests**

In `pkg/report/report_test.go`, a document with one found Adobe login row and one found MX row renders Adobe under `## Findings` and MX under `## Domain`. The bottom line does not call the MX row an email match. A document whose only subject is `SubjectIP` and whose geoip evidence contains `not a person or a street address` renders `## Infrastructure` and does not contain `No email matches`.

In `cmd/footprint/cli_test.go`, an email scan whose results include `ProfileURL: "https://github.com/octocat"` writes `Next: footprint scan username octocat` to stderr. The same scan with `username octocat` already set writes no `Next:` line. A profile URL with extra path segments (`https://github.com/octocat/repo`) writes no `Next:` line.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./pkg/report/ ./cmd/footprint/ -count=1`

Expected: FAIL because the MX row is still under Findings, or `Next:` is absent.

- [ ] **Step 3: Implement sections and the suggestion**

`writeFindings` includes only methods `register`, `login`, `password_reset`, `breach`, and `profile`. Add `writeGrouped` for method `dns` (`## Domain`), `infra` (`## Infrastructure`), and `entity` (`## Entity`), using the same three-column table. Skip a section when it has no found rows.

`bottomLine` counts email matches only for `register`, `login`, and `password_reset`. When `Email` and `Username` are empty, lead with the subject that is set and the found count for that module. Example: `Network notes for ` + the IP, or `Domain notes for ` + the domain. Keep the existing unchecked sentence.

Username suggestion, in the scan path after results are collected, stderr only:

```go
func suggestUsername(results []checker.Result, username string) string {
	if username != "" {
		return ""
	}
	for _, res := range results {
		if res.Status != checker.StatusFound || res.ProfileURL == "" {
			continue
		}
		u, err := url.Parse(res.ProfileURL)
		if err != nil {
			continue
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) != 1 || parts[0] == "" || strings.Contains(parts[0], ".") {
			continue
		}
		return parts[0]
	}
	return ""
}
```

`https://github.com/octocat` has one path segment and is suggested. `https://github.com/octocat/repo` has two and is not. Print `Next: footprint scan username %s\n` on stderr. Do not run the scan.

Add `pkg/domain`, `pkg/infra`, `pkg/entity`, and `pkg/casefile` to the layout table in `AGENTS.md`. State that `cmd/footprint-mcp` is not started until the local modules pass `go test ./...`.

- [ ] **Step 4: Run the tests**

Run: `go test ./pkg/report/ ./cmd/footprint/ ./pkg/... -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/report cmd/footprint/cli.go cmd/footprint/cli_test.go AGENTS.md
git commit -m "$(cat <<'EOF'
Keep network and organization findings out of the email section.

A profile URL can suggest a username scan, and the tool does not run that scan itself.
EOF
)"
```

### Task 8: Local gate

**Files:** none

- [ ] **Step 1: Run the offline suite**

Run: `go test ./... -count=1`

Expected: PASS, with no network.

- [ ] **Step 2: Stop**

Do not start Phase 2. Tell the user the local gate passed and wait for an explicit go-ahead to build the MCP server.

## Phase 2 — MCP, only after Task 8 and an explicit go-ahead

### Task 9: MCP server

**Files:**
- Create: `cmd/footprint-mcp/main.go`
- Create: `cmd/footprint-mcp/tools.go`
- Create: `cmd/footprint-mcp/tools_test.go`
- Modify: `go.mod`, `go.sum`
- Modify: `README.md`
- Modify: `AGENTS.md`

**Interfaces:**
- Consumes: `sites.Select`, `checker.Run`, `domain.Check`, `domain.Certificates`, `infra.Check`, `entity.Screen`, `entity.SEC`, `casefile.Load`, `casefile.Diff`, `report.Summarize`
- Produces: stdio MCP tools `scan_email`, `lookup_domain`, `lookup_ip`, `lookup_entity`, `diff_reports`, `list_sites`

- [ ] **Step 1: Write the failing test**

Test the tool handlers without a live MCP session. Each handler returns a struct with `Summary report.Summary` and `Results []checker.Result`, or for diff the `casefile.Delta`.

- `scan_email` on an empty site list returns a summary whose four counts are zero and a non-nil results slice.
- `lookup_domain` for `ada@example.com` uses a fake resolver and the recorded name is `example.com`. `certs: false` does not call the certificate function.
- `lookup_ip` for `10.1.1.1` does not call the TXT or HTTP fakes.
- `lookup_entity` for `someone@example.com` returns an error the handler surfaces as a tool error, not a `not_found` row.
- `diff_reports` on two temp JSON files classifies found-then-rate-limited as Unchecked.
- `list_sites` returns the registered site names.

Assert no handler accepts a field named `person`, `address`, `tax`, or `latitude`.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./cmd/footprint-mcp/ -count=1`

Expected: FAIL because the package does not exist.

- [ ] **Step 3: Implement the server**

Use `github.com/modelcontextprotocol/go-sdk`. Run `go get` for that module. If the module path has moved, stop and report it.

`main` serves stdio only. Do not bind a port.

Tool results use the summaries from `report.Summarize` over the full result list, including when the caller asked for found rows only. `only_found` filters the returned results and leaves the summary intact, matching `report.Build`.

`lookup_ip` passes a nil GeoIP unless the process has `FOOTPRINT_GEOIP` set to a readable file. A missing file is the existing `geoip database not configured` error row.

`lookup_entity` requires `sdn_path`. An email or IP `name` is a tool error.

`diff_reports` reads only the two paths it was given.

Do not register any other tool.

Document the stdio launch in `README.md`:

```bash
claude mcp add footprint -- footprint-mcp
```

- [ ] **Step 4: Run the tests**

Run: `go test ./cmd/footprint-mcp/ ./... -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/footprint-mcp go.mod go.sum README.md AGENTS.md
git commit -m "$(cat <<'EOF'
Expose the local checks over a stdio MCP server.

The server returns the same summaries as the CLI and does not add a person lookup.
EOF
)"
```

## Self-review

- Spec coverage: domain, certs, IP, entity, save, diff, note, case-note sections, username suggestion, and gated MCP each have a task. Passive DNS, OpenCorporates, tax records, and people search are absent on purpose.
- Identity evidence and the current case note are not re-implemented.
- `Check` signatures are stable from the task that defines them through the CLI and MCP tasks.
- Phase 2 does not start inside Phase 1.
