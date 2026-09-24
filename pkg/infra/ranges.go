package infra

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Range kinds. A match says who publishes the range, not who uses the address.
const (
	KindHosting = "hosting"
	KindCDN     = "cdn"
	KindTor     = "tor"
	KindVPN     = "vpn"
)

// RangeEntry is one published prefix and what its publisher says it is.
type RangeEntry struct {
	Prefix netip.Prefix
	Detail string
}

// RangeSource is a published IP range list. Whole lists are downloaded and
// matched locally, so the address being looked up is never sent.
type RangeSource struct {
	Name   string // cache file name
	Label  string // shown to the user
	Kind   string
	MaxAge time.Duration
	get    func(ctx context.Context, fetch Fetcher) ([]byte, error)
	parse  func(body []byte) ([]RangeEntry, error)
}

// RangeList is a parsed source.
type RangeList struct {
	Source  RangeSource
	Entries []RangeEntry
}

// RangeSet is what LoadRanges produced. Unavailable names sources with no
// usable copy; Stale names sources served from an old copy after a failed
// refresh.
type RangeSet struct {
	Lists       []RangeList
	Unavailable []string
	Stale       []string
}

// RangeFlag is a published list that contains the address.
type RangeFlag struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Prefix string `json:"prefix"`
	Detail string `json:"detail,omitempty"`
}

// RangeCache keeps downloaded lists under Dir. With Update false it only
// reads what is already there.
type RangeCache struct {
	Dir    string
	Fetch  Fetcher
	Update bool
	Now    func() time.Time
}

// DefaultRangeSources are the lists `lookup ip` checks.
func DefaultRangeSources() []RangeSource {
	day := 24 * time.Hour
	return []RangeSource{
		{Name: "aws", Label: "AWS", Kind: KindHosting, MaxAge: day,
			get: getURL("https://ip-ranges.amazonaws.com/ip-ranges.json"), parse: parseAWS},
		{Name: "gcp", Label: "Google Cloud", Kind: KindHosting, MaxAge: day,
			get: getURL("https://www.gstatic.com/ipranges/cloud.json"), parse: parseGCP},
		{Name: "azure", Label: "Azure", Kind: KindHosting, MaxAge: day,
			get: getAzure, parse: parseAzure},
		{Name: "oracle", Label: "Oracle Cloud", Kind: KindHosting, MaxAge: day,
			get: getURL("https://docs.oracle.com/iaas/tools/public_ip_ranges.json"), parse: parseOracle},
		{Name: "digitalocean", Label: "DigitalOcean", Kind: KindHosting, MaxAge: day,
			get: getURL("https://www.digitalocean.com/geo/google.csv"), parse: parseDigitalOcean},
		{Name: "cloudflare", Label: "Cloudflare", Kind: KindCDN, MaxAge: day,
			get: getURLs("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"), parse: parseLines},
		{Name: "fastly", Label: "Fastly", Kind: KindCDN, MaxAge: day,
			get: getURL("https://api.fastly.com/public-ip-list"), parse: parseFastly},
		{Name: "tor", Label: "Tor exit list", Kind: KindTor, MaxAge: time.Hour,
			get: getURL("https://check.torproject.org/torbulkexitlist"), parse: parseLines},
		{Name: "x4bnet-vpn", Label: "X4BNet VPN list", Kind: KindVPN, MaxAge: day,
			get: getURLs("https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
				"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt"), parse: parseLines},
	}
}

// LoadRanges reads each source from the cache, refreshing stale copies when
// Update is set. A failed refresh falls back to the old copy.
func (c RangeCache) LoadRanges(ctx context.Context, sources []RangeSource) RangeSet {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	lists := make([]*RangeList, len(sources))
	stale := make([]bool, len(sources))
	var wg sync.WaitGroup
	for i, src := range sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lists[i], stale[i] = c.load(ctx, src, now())
		}()
	}
	wg.Wait()
	var set RangeSet
	for i, list := range lists {
		switch {
		case list == nil:
			set.Unavailable = append(set.Unavailable, sources[i].Label)
		default:
			set.Lists = append(set.Lists, *list)
			if stale[i] {
				set.Stale = append(set.Stale, sources[i].Label)
			}
		}
	}
	return set
}

func (c RangeCache) load(ctx context.Context, src RangeSource, now time.Time) (*RangeList, bool) {
	path := filepath.Join(c.Dir, src.Name+".cache")
	cached, cachedErr := c.readCache(path, src)
	fresh := cachedErr == nil && now.Sub(cached.at) <= src.MaxAge
	if fresh || !c.Update || c.Fetch == nil {
		if cachedErr != nil {
			return nil, false
		}
		return &RangeList{Source: src, Entries: cached.entries}, !fresh
	}
	body, err := src.get(ctx, c.Fetch)
	if err == nil {
		var entries []RangeEntry
		if entries, err = src.parse(body); err == nil && len(entries) == 0 {
			err = errors.New("list is empty")
		}
		if err == nil {
			if c.Dir != "" {
				_ = writeCache(path, body)
			}
			return &RangeList{Source: src, Entries: entries}, false
		}
	}
	if cachedErr != nil {
		return nil, false
	}
	return &RangeList{Source: src, Entries: cached.entries}, true
}

type cachedList struct {
	at      time.Time
	entries []RangeEntry
}

func (c RangeCache) readCache(path string, src RangeSource) (cachedList, error) {
	if c.Dir == "" {
		return cachedList{}, errors.New("no cache directory")
	}
	info, err := os.Stat(path)
	if err != nil {
		return cachedList{}, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return cachedList{}, err
	}
	entries, err := src.parse(body)
	if err != nil || len(entries) == 0 {
		return cachedList{}, errors.New("cached list is not usable")
	}
	return cachedList{at: info.ModTime(), entries: entries}, nil
}

// writeCache replaces the file atomically so a crash never leaves half a list.
func writeCache(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Match returns one flag per list that contains addr, using the most
// specific prefix in each list.
func (s RangeSet) Match(addr netip.Addr) []RangeFlag {
	addr = addr.Unmap()
	var flags []RangeFlag
	for _, list := range s.Lists {
		best := -1
		for i, e := range list.Entries {
			if e.Prefix.Contains(addr) && (best < 0 || e.Prefix.Bits() > list.Entries[best].Prefix.Bits()) {
				best = i
			}
		}
		if best >= 0 {
			e := list.Entries[best]
			flags = append(flags, RangeFlag{Kind: list.Source.Kind, Source: list.Source.Label, Prefix: e.Prefix.String(), Detail: e.Detail})
		}
	}
	return flags
}

func getURL(url string) func(context.Context, Fetcher) ([]byte, error) {
	return getURLs(url)
}

// getURLs joins several text bodies with newlines. Every part must succeed.
func getURLs(urls ...string) func(context.Context, Fetcher) ([]byte, error) {
	return func(ctx context.Context, fetch Fetcher) ([]byte, error) {
		var out bytes.Buffer
		for _, url := range urls {
			body, status, err := fetch.Get(ctx, url)
			if err != nil {
				return nil, err
			}
			if status != 200 {
				return nil, fmt.Errorf("%s returned %d", url, status)
			}
			out.Write(body)
			out.WriteByte('\n')
		}
		return out.Bytes(), nil
	}
}

var azureLink = regexp.MustCompile(`https://download\.microsoft\.com/[^"'\s]*ServiceTags_Public_\d+\.json`)

// getAzure reads the weekly file's link off Microsoft's download page; the
// file name changes every week.
func getAzure(ctx context.Context, fetch Fetcher) ([]byte, error) {
	page, err := getURL("https://www.microsoft.com/en-us/download/details.aspx?id=56519")(ctx, fetch)
	if err != nil {
		return nil, err
	}
	link := azureLink.Find(page)
	if link == nil {
		return nil, errors.New("azure download link not found")
	}
	return getURL(string(link))(ctx, fetch)
}

func addEntry(out []RangeEntry, prefix, detail string) []RangeEntry {
	p, err := netip.ParsePrefix(strings.TrimSpace(prefix))
	if err != nil {
		return out
	}
	return append(out, RangeEntry{Prefix: p.Masked(), Detail: detail})
}

func parseAWS(body []byte) ([]RangeEntry, error) {
	var doc struct {
		Prefixes []struct {
			Prefix  string `json:"ip_prefix"`
			Region  string `json:"region"`
			Service string `json:"service"`
		} `json:"prefixes"`
		IPv6 []struct {
			Prefix  string `json:"ipv6_prefix"`
			Region  string `json:"region"`
			Service string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	// AWS lists most prefixes twice: once as AMAZON and once as the service.
	// Keep the service names and drop AMAZON where another name exists.
	type key struct{ prefix, region string }
	services := map[key][]string{}
	var order []key
	add := func(prefix, region, service string) {
		k := key{prefix, region}
		if _, ok := services[k]; !ok {
			order = append(order, k)
		}
		services[k] = append(services[k], service)
	}
	for _, p := range doc.Prefixes {
		add(p.Prefix, p.Region, p.Service)
	}
	for _, p := range doc.IPv6 {
		add(p.Prefix, p.Region, p.Service)
	}
	var out []RangeEntry
	for _, k := range order {
		names := services[k]
		if len(names) > 1 {
			kept := names[:0]
			for _, n := range names {
				if n != "AMAZON" {
					kept = append(kept, n)
				}
			}
			names = kept
		}
		sort.Strings(names)
		out = addEntry(out, k.prefix, joinDetail(strings.Join(names, ", "), k.region))
	}
	return out, nil
}

func parseGCP(body []byte) ([]RangeEntry, error) {
	var doc struct {
		Prefixes []struct {
			V4    string `json:"ipv4Prefix"`
			V6    string `json:"ipv6Prefix"`
			Scope string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []RangeEntry
	for _, p := range doc.Prefixes {
		prefix := p.V4
		if prefix == "" {
			prefix = p.V6
		}
		out = addEntry(out, prefix, p.Scope)
	}
	return out, nil
}

func parseAzure(body []byte) ([]RangeEntry, error) {
	var doc struct {
		Values []struct {
			Name       string `json:"name"`
			Properties struct {
				Region   string   `json:"region"`
				Prefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []RangeEntry
	for _, v := range doc.Values {
		// AzureCloud.<region> covers every public Azure range once, by region.
		if !strings.HasPrefix(v.Name, "AzureCloud.") {
			continue
		}
		for _, p := range v.Properties.Prefixes {
			out = addEntry(out, p, v.Properties.Region)
		}
	}
	return out, nil
}

func parseOracle(body []byte) ([]RangeEntry, error) {
	var doc struct {
		Regions []struct {
			Region string `json:"region"`
			CIDRs  []struct {
				CIDR string `json:"cidr"`
			} `json:"cidrs"`
		} `json:"regions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []RangeEntry
	for _, r := range doc.Regions {
		for _, c := range r.CIDRs {
			out = addEntry(out, c.CIDR, r.Region)
		}
	}
	return out, nil
}

// parseDigitalOcean reads the geofeed CSV: prefix, country, region, city, postal.
func parseDigitalOcean(body []byte) ([]RangeEntry, error) {
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []RangeEntry
	for _, rec := range records {
		if len(rec) == 0 {
			continue
		}
		detail := ""
		if len(rec) > 3 {
			detail = joinDetail(rec[3], rec[1])
		}
		out = addEntry(out, rec[0], detail)
	}
	return out, nil
}

func parseFastly(body []byte) ([]RangeEntry, error) {
	var doc struct {
		V4 []string `json:"addresses"`
		V6 []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []RangeEntry
	for _, p := range append(doc.V4, doc.V6...) {
		out = addEntry(out, p, "")
	}
	return out, nil
}

// parseLines reads one prefix or address per line. Blank lines and # comments
// are skipped; a bare address is a single-host prefix.
func parseLines(body []byte) ([]RangeEntry, error) {
	var out []RangeEntry
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "/") {
			addr, err := netip.ParseAddr(line)
			if err != nil {
				continue
			}
			out = append(out, RangeEntry{Prefix: netip.PrefixFrom(addr, addr.BitLen())})
			continue
		}
		out = addEntry(out, line, "")
	}
	return out, sc.Err()
}

func joinDetail(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, " · ")
}
