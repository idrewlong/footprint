package infra

import (
	"context"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/idrewlong/footprint/pkg/checker"
)

type fakeInfra struct {
	addr    []string
	addrErr error
	hosts   map[string][]string
	hostErr error
	txt     map[string][]string
	txtErr  error
}

func (f *fakeInfra) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return f.addr, f.addrErr
}

func (f *fakeInfra) LookupHost(ctx context.Context, host string) ([]string, error) {
	if f.hostErr != nil {
		return nil, f.hostErr
	}
	addrs, ok := f.hosts[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
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
		// Coordinates belong in the profile panel with their radius, not the row sentence.
		t.Fatalf("coordinates in row: %+v", row)
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

func TestGeoIPEmptyPlaceIsNotFound(t *testing.T) {
	rows, err := Check(context.Background(), &fakeInfra{}, fakeGeo{place: Place{}}, nil, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	row := rowBySite(rows, "geoip")
	if row.Status != checker.StatusNotFound {
		t.Fatalf("%+v", row)
	}
	if row.Evidence != "The GeoIP database has no record for this address." {
		t.Fatalf("evidence=%q", row.Evidence)
	}
}

func TestDocumentationPrefixIsNotSent(t *testing.T) {
	dns := &fakeInfra{}
	fetch := &fakeFetch{}
	rows, err := Check(context.Background(), dns, fakeGeo{}, fetch, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(dns.txt) != 0 || fetch.called {
		t.Fatal("documentation address was sent")
	}
	for _, site := range []string{"asn", "geoip", "rdap"} {
		row := rowBySite(rows, site)
		if row.Status != checker.StatusError {
			t.Fatalf("%s %+v", site, row)
		}
	}
}

func TestASNIPv6UsesOrigin6(t *testing.T) {
	name := "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com"
	dns := &fakeInfra{txt: map[string][]string{
		name:                    {"15169 | 2001:4860::/32 | US | arin | 2005-03-14"},
		"AS15169.asn.cymru.com": {"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"},
	}}
	p, rows, err := Lookup(context.Background(), Sources{DNS: dns}, "2001:4860:4860::8888")
	if err != nil {
		t.Fatal(err)
	}
	if asn := rowBySite(rows, "asn"); asn.Status != checker.StatusFound {
		t.Fatalf("%+v", asn)
	}
	if p.ASN != "15169" || p.Prefix != "2001:4860::/32" || p.ASName != "GOOGLE - Google LLC, US" || p.Version != "IPv6" {
		t.Fatalf("%+v", p)
	}
}

func TestForwardConfirm(t *testing.T) {
	cases := []struct {
		name    string
		hosts   map[string][]string
		hostErr error
		want    string
	}{
		{"confirmed", map[string][]string{"h.example": {"1.1.1.1", "8.8.8.8"}}, nil, "confirmed"},
		{"elsewhere", map[string][]string{"h.example": {"1.1.1.1"}}, nil, "mismatch"},
		{"no such name", nil, nil, "mismatch"},
		{"server failure is unknown", nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dns := &fakeInfra{addr: []string{"h.example."}, hosts: tc.hosts, hostErr: tc.hostErr}
			p, rows, err := Lookup(context.Background(), Sources{DNS: dns}, "8.8.8.8")
			if err != nil {
				t.Fatal(err)
			}
			if p.HostnameCheck != tc.want {
				t.Fatalf("check=%q want %q", p.HostnameCheck, tc.want)
			}
			if ptr := rowBySite(rows, "ptr"); ptr.Status != checker.StatusFound {
				t.Fatalf("%+v", ptr)
			}
		})
	}
}

func TestRDAP404Evidence(t *testing.T) {
	fetch := &fakeFetch{status: 404, body: []byte("missing")}
	rows, err := Check(context.Background(), &fakeInfra{}, nil, fetch, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	row := rowBySite(rows, "rdap")
	if row.Status != checker.StatusNotFound || row.Evidence != "RDAP has no registration record for this address." {
		t.Fatalf("%+v", row)
	}
}

func TestOpenGeoIPMissingFile(t *testing.T) {
	_, err := OpenGeoIP(filepath.Join(t.TempDir(), "missing.mmdb"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLookupFillsProfile(t *testing.T) {
	dns := &fakeInfra{
		addr:  []string{"dns.google."},
		hosts: map[string][]string{"dns.google": {"8.8.4.4", "8.8.8.8"}},
		txt: map[string][]string{
			"8.8.8.8.origin.asn.cymru.com": {"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"},
			"AS15169.asn.cymru.com":        {"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"},
		},
	}
	geo := fakeGeo{place: Place{City: "Mountain View", Region: "California", PostalCode: "94043", Country: "United States", CountryCode: "US", TimeZone: "America/Los_Angeles"}}
	fetch := &fakeFetch{status: 200, body: []byte(`{
		"handle":"NET-8-8-8-0-2","name":"GOGL","startAddress":"8.8.8.0","endAddress":"8.8.8.255",
		"cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}],
		"entities":[
			{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse Desk"]]]},
			{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"]]]}
		]}`)}
	p, rows, err := Lookup(context.Background(), Sources{DNS: dns, GeoIP: geo, Fetch: fetch}, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	want := Profile{
		IP: "8.8.8.8", Version: "IPv4", Public: true, Hostname: "dns.google", HostnameCheck: "confirmed",
		City: "Mountain View", Region: "California", PostalCode: "94043", Country: "United States", CountryCode: "US", TimeZone: "America/Los_Angeles",
		ASN: "15169", ASName: "GOOGLE - Google LLC, US", Prefix: "8.8.8.0/24", Registry: "arin",
		Network: "GOGL", NetworkHandle: "NET-8-8-8-0-2", NetworkRange: "8.8.8.0/24", Organization: "Google LLC",
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("profile\n got %+v\nwant %+v", p, want)
	}
	if asn := rowBySite(rows, "asn"); !strings.Contains(asn.Evidence, "GOOGLE - Google LLC, US") {
		t.Fatalf("%+v", asn)
	}
	if rdap := rowBySite(rows, "rdap"); !strings.Contains(rdap.Evidence, "registered to Google LLC") {
		t.Fatalf("%+v", rdap)
	}
}

func TestASNNameFailureKeepsASN(t *testing.T) {
	dns := &fakeInfra{txt: map[string][]string{
		"4.3.2.1.origin.asn.cymru.com": {"15169 | 1.2.3.0/24 | US | arin | 2000-03-30"},
	}}
	p, rows, err := Lookup(context.Background(), Sources{DNS: dns, GeoIP: nil, Fetch: nil}, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if asn := rowBySite(rows, "asn"); asn.Status != checker.StatusFound || p.ASN != "15169" || p.ASName != "" {
		t.Fatalf("%+v %+v", asn, p)
	}
}

func TestRDAPRangeFallsBackToAddresses(t *testing.T) {
	fetch := &fakeFetch{status: 200, body: []byte(`{"handle":"H","name":"N","startAddress":"1.2.3.0","endAddress":"1.2.3.127"}`)}
	p, _, err := Lookup(context.Background(), Sources{DNS: &fakeInfra{}, GeoIP: nil, Fetch: fetch}, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if p.NetworkRange != "1.2.3.0 – 1.2.3.127" || p.Organization != "" {
		t.Fatalf("%+v", p)
	}
}

func TestPrivateProfileHasNoLookups(t *testing.T) {
	p, _, err := Lookup(context.Background(), Sources{DNS: &fakeInfra{}, GeoIP: fakeGeo{place: Place{City: "X"}}, Fetch: &fakeFetch{}}, "10.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, Profile{IP: "10.1.1.1", Version: "IPv4"}) {
		t.Fatalf("%+v", p)
	}
}

func TestCoordinatesNeedARadius(t *testing.T) {
	lat, lon := 47.2513, -122.3149
	with := fakeGeo{place: Place{City: "Milton", Latitude: &lat, Longitude: &lon, AccuracyKM: 22}}
	p, _, err := Lookup(context.Background(), Sources{DNS: &fakeInfra{}, GeoIP: with, Fetch: nil}, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if p.Latitude == nil || *p.Latitude != lat || p.Longitude == nil || *p.Longitude != lon || p.AccuracyKM != 22 {
		t.Fatalf("%+v", p)
	}
	without := fakeGeo{place: Place{City: "Milton", Latitude: &lat, Longitude: &lon}}
	p, _, err = Lookup(context.Background(), Sources{DNS: &fakeInfra{}, GeoIP: without, Fetch: nil}, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if p.Latitude != nil || p.Longitude != nil || p.AccuracyKM != 0 {
		t.Fatalf("point without a radius reached the profile: %+v", p)
	}
}
