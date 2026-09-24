package infra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/idrewlong/footprint/internal/httpx"
	"github.com/idrewlong/footprint/pkg/checker"
)

// Resolver is the DNS surface Check needs. Tests supply a fake.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Place is a network location from a GeoIP database. Country is the English
// name when the database has one; CountryCode is the ISO code. Latitude and
// Longitude are nil when the database has no point; AccuracyKM is the
// database's radius around that point.
type Place struct {
	City, Region, PostalCode, Country, CountryCode, TimeZone string
	Latitude, Longitude                                      *float64
	AccuracyKM                                               int
}

// Profile is the at-a-glance view of an IP address. Every field comes from
// the same lookups as the result rows. An empty field means the lookup had
// no value or did not run; the rows say which.
type Profile struct {
	IP       string `json:"ip"`
	Version  string `json:"version"`
	Public   bool   `json:"public"`
	Hostname string `json:"hostname,omitempty"`
	// HostnameCheck is "confirmed" when the hostname resolves back to this
	// address, "mismatch" when it resolves elsewhere or not at all, and
	// empty when the forward lookup could not be completed.
	HostnameCheck string   `json:"hostname_check,omitempty"`
	City          string   `json:"city,omitempty"`
	Region        string   `json:"region,omitempty"`
	PostalCode    string   `json:"postal_code,omitempty"`
	Country       string   `json:"country,omitempty"`
	CountryCode   string   `json:"country_code,omitempty"`
	TimeZone      string   `json:"time_zone,omitempty"`
	Latitude      *float64 `json:"latitude,omitempty"`
	Longitude     *float64 `json:"longitude,omitempty"`
	AccuracyKM    int      `json:"accuracy_km,omitempty"`
	ASN           string   `json:"asn,omitempty"`
	ASName        string   `json:"as_name,omitempty"`
	Prefix        string   `json:"prefix,omitempty"`
	Registry      string   `json:"registry,omitempty"`
	Network       string   `json:"network,omitempty"`
	NetworkHandle string   `json:"network_handle,omitempty"`
	NetworkRange  string   `json:"network_range,omitempty"`
	Organization  string   `json:"organization,omitempty"`
	// Flags lists the published range lists that contain the address.
	// RangesChecked counts the lists that were read; Unavailable and Stale
	// name lists that could not be read or were served from an old copy.
	Flags             []RangeFlag `json:"flags,omitempty"`
	RangesChecked     int         `json:"ranges_checked,omitempty"`
	RangesUnavailable []string    `json:"ranges_unavailable,omitempty"`
	RangesStale       []string    `json:"ranges_stale,omitempty"`
}

// Sources are the lookups Lookup uses. A nil field makes its row an error.
type Sources struct {
	DNS    Resolver
	GeoIP  GeoIP
	Fetch  Fetcher
	Ranges *RangeSet
}

// GeoIP looks up a network place for an IP. A nil GeoIP is an error row.
type GeoIP interface {
	Lookup(ip net.IP) (Place, error)
}

// Fetcher is the HTTP surface RDAP needs. Tests supply a fake.
type Fetcher interface {
	Get(ctx context.Context, url string) ([]byte, int, error)
}

var (
	cgnatNet  = mustCIDR("100.64.0.0/10")
	docNet    = mustCIDR("2001:db8::/32")
	testNet1  = mustCIDR("192.0.2.0/24")
	testNet2  = mustCIDR("198.51.100.0/24")
	testNet3  = mustCIDR("203.0.113.0/24")
	futureNet = mustCIDR("240.0.0.0/4")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// Check reports reverse DNS, ASN, GeoIP, and RDAP for an IP address.
// An unparseable string returns an error so the CLI can exit 2.
func Check(ctx context.Context, r Resolver, geo GeoIP, fetch Fetcher, ip string) ([]checker.Result, error) {
	_, rows, err := Lookup(ctx, Sources{DNS: r, GeoIP: geo, Fetch: fetch}, ip)
	return rows, err
}

// IsPublic reports whether ip parses and is a public address. Only public
// addresses go to public lookups or need the range lists.
func IsPublic(ip string) bool {
	return isPublic(net.ParseIP(ip))
}

// Lookup runs the same checks as Check, plus the published range lists when
// src.Ranges is set, and returns the Profile they fill.
func Lookup(ctx context.Context, src Sources, ip string) (Profile, []checker.Result, error) {
	r, geo, fetch := src.DNS, src.GeoIP, src.Fetch
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Profile{}, nil, fmt.Errorf("ip address is not valid")
	}
	pub := isPublic(parsed)
	p := Profile{IP: parsed.String(), Version: "IPv6", Public: pub}
	if parsed.To4() != nil {
		p.Version = "IPv4"
	}
	rows := []checker.Result{
		checkPTR(ctx, r, ip, &p),
		checkASN(ctx, r, ip, parsed, pub, &p),
		checkGeoIP(geo, ip, parsed, pub, &p),
		checkRDAP(ctx, fetch, ip, pub, &p),
	}
	if src.Ranges != nil {
		rows = append(rows, checkRanges(src.Ranges, ip, parsed, pub, &p))
	}
	return p, rows, nil
}

func isPublic(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if cgnatNet.Contains(ip) || docNet.Contains(ip) {
		return false
	}
	if testNet1.Contains(ip) || testNet2.Contains(ip) || testNet3.Contains(ip) || futureNet.Contains(ip) {
		return false
	}
	return true
}

func baseResult(site, ip string) checker.Result {
	return checker.Result{Site: site, Domain: ip, Category: "infra", Method: "infra"}
}

func privateBlocked(site, ip string) checker.Result {
	row := baseResult(site, ip)
	row.Status = checker.StatusError
	row.Detail = "private address is not sent to a public lookup"
	return row
}

func checkPTR(ctx context.Context, r Resolver, ip string, p *Profile) checker.Result {
	row := baseResult("ptr", ip)
	names, err := r.LookupAddr(ctx, ip)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			row.Status = checker.StatusNotFound
			row.Evidence = "Reverse DNS has no name for this address."
			return row
		}
		row.Status = checker.StatusError
		row.Detail = "dns lookup failed"
		return row
	}
	if len(names) == 0 {
		row.Status = checker.StatusNotFound
		row.Evidence = "Reverse DNS has no name for this address."
		return row
	}
	host := strings.TrimSuffix(names[0], ".")
	p.Hostname = host
	row.Status = checker.StatusFound
	row.Evidence = "Reverse DNS names this address " + host + "."
	switch p.HostnameCheck = forwardConfirm(ctx, r, host, ip); p.HostnameCheck {
	case "confirmed":
		row.Evidence += " The name resolves back to this address."
	case "mismatch":
		row.Evidence += " The name does not resolve back to this address, so only the network owner's reverse DNS vouches for it."
	}
	return row
}

// forwardConfirm resolves host and compares the answers with ip. A lookup
// that fails for any reason other than "no such name" is unknown, not a
// mismatch.
func forwardConfirm(ctx context.Context, r Resolver, host, ip string) string {
	want := net.ParseIP(ip)
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "mismatch"
		}
		return ""
	}
	for _, a := range addrs {
		if got := net.ParseIP(a); got != nil && got.Equal(want) {
			return "confirmed"
		}
	}
	return "mismatch"
}

func checkASN(ctx context.Context, r Resolver, ip string, parsed net.IP, pub bool, p *Profile) checker.Result {
	if !pub {
		return privateBlocked("asn", ip)
	}
	row := baseResult("asn", ip)
	name, ok := cymruOriginName(parsed)
	if !ok {
		row.Status = checker.StatusError
		row.Detail = "asn lookup name could not be built"
		return row
	}
	txt, err := r.LookupTXT(ctx, name)
	if err != nil {
		row.Status = checker.StatusError
		row.Detail = "dns lookup failed"
		return row
	}
	if len(txt) == 0 {
		row.Status = checker.StatusError
		row.Detail = "asn payload not understood"
		return row
	}
	fields := cymruFields(txt[0])
	asn := fields[0]
	if asn == "" {
		row.Status = checker.StatusError
		row.Detail = "asn payload not understood"
		return row
	}
	// A prefix announced by several origins lists them space-separated.
	p.ASN = strings.Fields(asn)[0]
	p.Prefix, p.Registry = fields[1], fields[3]
	// The AS name is a second lookup keyed by the AS number, not the IP.
	// A failure leaves the name empty; the origin answer still stands.
	if names, err := r.LookupTXT(ctx, "AS"+p.ASN+".asn.cymru.com"); err == nil && len(names) > 0 {
		p.ASName = cymruFields(names[0])[4]
	}
	row.Status = checker.StatusFound
	row.Evidence = "Team Cymru DNS lists AS" + asn
	if p.ASName != "" {
		row.Evidence += " (" + p.ASName + ")"
	}
	row.Evidence += " for this address. The registry country is the network's country, not a person's location."
	return row
}

// cymruFields splits a Team Cymru TXT answer into five trimmed fields.
// Missing fields are empty.
func cymruFields(txt string) [5]string {
	var out [5]string
	for i, f := range strings.SplitN(txt, "|", 5) {
		out[i] = strings.TrimSpace(f)
	}
	return out
}

func cymruOriginName(ip net.IP) (string, bool) {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0]), true
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", false
	}
	// IPv6 uses all 32 nibbles, least significant first.
	const hex = "0123456789abcdef"
	var b strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		b.WriteByte(hex[v6[i]&0x0f])
		b.WriteByte('.')
		b.WriteByte(hex[v6[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("origin6.asn.cymru.com")
	return b.String(), true
}

func checkGeoIP(geo GeoIP, ip string, parsed net.IP, pub bool, p *Profile) checker.Result {
	if !pub {
		return privateBlocked("geoip", ip)
	}
	row := baseResult("geoip", ip)
	if geo == nil {
		row.Status = checker.StatusError
		row.Detail = "geoip database not configured"
		return row
	}
	place, err := geo.Lookup(parsed)
	if err != nil {
		row.Status = checker.StatusError
		row.Detail = "geoip lookup failed"
		return row
	}
	country := place.Country
	if country == "" {
		country = place.CountryCode
	}
	parts := make([]string, 0, 3)
	for _, part := range []string{place.City, place.Region, country} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		row.Status = checker.StatusNotFound
		row.Evidence = "The GeoIP database has no record for this address."
		return row
	}
	p.City, p.Region, p.PostalCode = place.City, place.Region, place.PostalCode
	p.Country, p.CountryCode, p.TimeZone = place.Country, place.CountryCode, place.TimeZone
	// Coordinates go to the profile only as a pair, and only with a radius,
	// so a point is never shown without how wide it is.
	if place.Latitude != nil && place.Longitude != nil && place.AccuracyKM > 0 {
		p.Latitude, p.Longitude, p.AccuracyKM = place.Latitude, place.Longitude, place.AccuracyKM
	}
	row.Status = checker.StatusFound
	row.Evidence = "GeoIP database places this address in " + strings.Join(parts, ", ") + ". This is the network's city, not a person or a street address."
	return row
}

func checkRDAP(ctx context.Context, fetch Fetcher, ip string, pub bool, p *Profile) checker.Result {
	if !pub {
		return privateBlocked("rdap", ip)
	}
	row := baseResult("rdap", ip)
	if fetch == nil {
		row.Status = checker.StatusError
		row.Detail = "rdap client not configured"
		return row
	}
	body, status, err := fetch.Get(ctx, "https://rdap.org/ip/"+ip)
	if err != nil {
		row.Status = checker.StatusError
		row.Detail = "rdap request failed"
		return row
	}
	if httpx.IsLimited(status, body) {
		row.Status = checker.StatusRateLimited
		return row
	}
	switch status {
	case 404:
		row.Status = checker.StatusNotFound
		row.Evidence = "RDAP has no registration record for this address."
		return row
	case 200:
		var payload rdapNetwork
		if err := json.Unmarshal(body, &payload); err != nil || payload.Name == "" {
			row.Status = checker.StatusError
			row.Detail = "rdap request failed"
			return row
		}
		p.Network, p.NetworkHandle = payload.Name, payload.Handle
		p.NetworkRange = payload.rangeText()
		p.Organization = payload.registrant()
		row.Status = checker.StatusFound
		row.Evidence = "RDAP lists network " + payload.Name + " (" + payload.Handle + ")"
		if p.Organization != "" {
			row.Evidence += ", registered to " + p.Organization
		}
		row.Evidence += ". This is the registered network, not a person."
		return row
	default:
		row.Status = checker.StatusError
		row.Detail = "rdap request failed"
		return row
	}
}

type rdapNetwork struct {
	Handle       string `json:"handle"`
	Name         string `json:"name"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	CIDRs        []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
	Entities []struct {
		Roles []string          `json:"roles"`
		VCard []json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
}

// rangeText prefers the cidr0 extension and falls back to start and end.
func (n rdapNetwork) rangeText() string {
	var cidrs []string
	for _, c := range n.CIDRs {
		prefix := c.V4Prefix
		if prefix == "" {
			prefix = c.V6Prefix
		}
		if prefix != "" {
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", prefix, c.Length))
		}
	}
	if len(cidrs) > 0 {
		return strings.Join(cidrs, ", ")
	}
	if n.StartAddress != "" && n.EndAddress != "" {
		return n.StartAddress + " – " + n.EndAddress
	}
	return ""
}

// registrant returns the vCard full name of the first registrant entity.
func (n rdapNetwork) registrant() string {
	for _, e := range n.Entities {
		if !slices.Contains(e.Roles, "registrant") || len(e.VCard) < 2 {
			continue
		}
		var props [][]json.RawMessage
		if err := json.Unmarshal(e.VCard[1], &props); err != nil {
			continue
		}
		for _, prop := range props {
			var name, value string
			if len(prop) < 4 || json.Unmarshal(prop[0], &name) != nil || name != "fn" {
				continue
			}
			if json.Unmarshal(prop[3], &value) == nil && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func checkRanges(set *RangeSet, ip string, parsed net.IP, pub bool, p *Profile) checker.Result {
	row := baseResult("ranges", ip)
	if !pub {
		row.Status = checker.StatusNotFound
		row.Evidence = "Published cloud, CDN, Tor, and VPN lists cover public addresses only."
		return row
	}
	addr, ok := netip.AddrFromSlice(parsed)
	if !ok {
		row.Status = checker.StatusError
		row.Detail = "address could not be matched"
		return row
	}
	p.RangesChecked = len(set.Lists)
	p.RangesUnavailable = set.Unavailable
	p.RangesStale = set.Stale
	p.Flags = set.Match(addr)
	var notes []string
	if len(set.Unavailable) > 0 {
		notes = append(notes, "could not load "+strings.Join(set.Unavailable, ", "))
	}
	if len(set.Stale) > 0 {
		notes = append(notes, "old copy of "+strings.Join(set.Stale, ", "))
	}
	row.Detail = strings.Join(notes, "; ")
	if len(p.Flags) > 0 {
		names := make([]string, len(p.Flags))
		for i, f := range p.Flags {
			names[i] = f.Source
		}
		row.Status = checker.StatusFound
		row.Evidence = "Published range lists contain this address: " + strings.Join(names, ", ") + ". A list names who publishes the range, not who used the address."
		return row
	}
	// A miss counts only when every list was read.
	if len(set.Unavailable) > 0 || len(set.Lists) == 0 {
		row.Status = checker.StatusError
		if row.Detail == "" {
			row.Detail = "no range lists loaded"
		}
		return row
	}
	row.Status = checker.StatusNotFound
	row.Evidence = fmt.Sprintf("None of %d published cloud, CDN, Tor, and VPN lists contain this address.", len(set.Lists))
	return row
}
