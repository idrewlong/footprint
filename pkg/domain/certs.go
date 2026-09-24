package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/idrewlong/footprint/internal/httpx"
	"github.com/idrewlong/footprint/pkg/checker"
)

type certEntry struct {
	CommonName string `json:"common_name"`
}

// Certificates reports how many crt.sh entries match a domain.
// The caller supplies get so tests can avoid network access.
func Certificates(ctx context.Context, get func(context.Context, string) ([]byte, int, error), domain string) checker.Result {
	base := checker.Result{Site: "certs", Domain: domain, Category: "domain", Method: "dns"}

	params := url.Values{}
	params.Set("q", domain)
	params.Set("output", "json")
	reqURL := "https://crt.sh/?" + params.Encode()

	body, status, err := get(ctx, reqURL)
	if err != nil {
		base.Status = checker.StatusError
		base.Detail = "crt.sh response not understood"
		return base
	}
	if httpx.IsLimited(status, body) {
		base.Status = checker.StatusRateLimited
		return base
	}
	if status != 200 {
		base.Status = checker.StatusError
		base.Detail = "crt.sh response not understood"
		return base
	}

	var entries []certEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		base.Status = checker.StatusError
		base.Detail = "crt.sh response not understood"
		return base
	}
	if len(entries) == 0 {
		base.Status = checker.StatusNotFound
		base.Evidence = "crt.sh lists no certificates for this domain."
		return base
	}

	names := make(map[string]struct{})
	for _, entry := range entries {
		name := strings.TrimSpace(entry.CommonName)
		if name != "" {
			names[name] = struct{}{}
		}
	}

	unique := make([]string, 0, len(names))
	for name := range names {
		unique = append(unique, name)
	}
	sort.Strings(unique)
	if len(unique) > 20 {
		unique = unique[:20]
	}

	base.Status = checker.StatusFound
	base.Evidence = fmt.Sprintf("crt.sh lists %d certificates for this domain.", len(entries))
	base.Detail = strings.Join(unique, ", ")
	return base
}
