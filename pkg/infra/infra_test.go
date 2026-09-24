package infra

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/idrewlong/footprint/pkg/checker"
)

type fakeInfra struct {
	addr    []string
	addrErr error
	txt     map[string][]string
	txtErr  error
}

func (f *fakeInfra) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return f.addr, f.addrErr
}

func (f *fakeInfra) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if f.txt == nil {
		f.txt = map[string][]string{}
	}
	if _, ok := f.txt[name]; !ok {
		f.txt[name] = nil
	}
	if f.txtErr != nil {
		return nil, f.txtErr
	}
	return f.txt[name], nil
}

type fakeFetch struct {
	status int
	body   []byte
	err    error
	called bool
	url    string
}

func (f *fakeFetch) Get(ctx context.Context, url string) ([]byte, int, error) {
	f.called = true
	f.url = url
	return f.body, f.status, f.err
}

type fakeGeo struct {
	place Place
	err   error
}

func (f fakeGeo) Lookup(ip net.IP) (Place, error) {
	return f.place, f.err
}

func rowBySite(rows []checker.Result, site string) checker.Result {
	for _, row := range rows {
		if row.Site == site {
			return row
		}
	}
	return checker.Result{}
}

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
