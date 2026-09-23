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
