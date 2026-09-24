package infra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/idrewlong/footprint/pkg/checker"
)

// Resolver is the DNS surface Check needs. Tests supply a fake.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Place is a network location from a GeoIP database.
type Place struct {
	City, Region, Country string
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
	cgnatNet = mustCIDR("100.64.0.0/10")
	docNet   = mustCIDR("2001:db8::/32")
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
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("ip address is not valid")
	}
	pub := isPublic(parsed)
	return []checker.Result{
		checkPTR(ctx, r, ip),
		checkASN(ctx, r, ip, parsed, pub),
		checkGeoIP(geo, ip, parsed, pub),
		checkRDAP(ctx, fetch, ip, pub),
	}, nil
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

func checkPTR(ctx context.Context, r Resolver, ip string) checker.Result {
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
		return row
	}
	if len(names) == 0 {
		row.Status = checker.StatusNotFound
		row.Evidence = "Reverse DNS has no name for this address."
		return row
	}
	host := strings.TrimSuffix(names[0], ".")
	row.Status = checker.StatusFound
	row.Evidence = "Reverse DNS names this address " + host + "."
	return row
}

func checkASN(ctx context.Context, r Resolver, ip string, parsed net.IP, pub bool) checker.Result {
	if !pub {
		return privateBlocked("asn", ip)
	}
	row := baseResult("asn", ip)
	name, ok := cymruOriginName(parsed)
	if !ok {
		row.Status = checker.StatusError
		return row
	}
	txt, err := r.LookupTXT(ctx, name)
	if err != nil {
		row.Status = checker.StatusError
		return row
	}
	if len(txt) == 0 {
		row.Status = checker.StatusError
		return row
	}
	asn := strings.TrimSpace(strings.Split(txt[0], "|")[0])
	if asn == "" {
		row.Status = checker.StatusError
		return row
	}
	row.Status = checker.StatusFound
	row.Evidence = "Team Cymru DNS lists AS" + asn + " for this address. The registry country is the network's country, not a person's location."
	return row
}

func cymruOriginName(ip net.IP) (string, bool) {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0]), true
	}
	return "", false
}

func checkGeoIP(geo GeoIP, ip string, parsed net.IP, pub bool) checker.Result {
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
		return row
	}
	parts := make([]string, 0, 3)
	for _, p := range []string{place.City, place.Region, place.Country} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	row.Status = checker.StatusFound
	row.Evidence = "GeoIP database places this address in " + strings.Join(parts, ", ") + ". This is the network's city, not a person or a street address."
	return row
}

func checkRDAP(ctx context.Context, fetch Fetcher, ip string, pub bool) checker.Result {
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
		return row
	}
	switch status {
	case 404:
		row.Status = checker.StatusNotFound
		return row
	case 429:
		row.Status = checker.StatusRateLimited
		return row
	case 200:
		var payload struct {
			Handle string `json:"handle"`
			Name   string `json:"name"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || payload.Name == "" {
			row.Status = checker.StatusError
			return row
		}
		row.Status = checker.StatusFound
		row.Evidence = "RDAP lists network " + payload.Name + " (" + payload.Handle + "). This is the registered network, not a person."
		return row
	default:
		row.Status = checker.StatusError
		return row
	}
}
