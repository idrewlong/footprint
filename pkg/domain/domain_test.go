package domain

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/idrewlong/footprint/pkg/checker"
)

type fakeDNS struct {
	mx     []*net.MX
	mxErr  error
	txt    map[string][]string
	txtErr map[string]error
	seen   []string
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
			"example.com":        {"v=spf1 mx -all"},
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
