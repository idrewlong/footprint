package infra

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

func TestParseAWSDropsDuplicateAMAZON(t *testing.T) {
	body := []byte(`{"prefixes":[
		{"ip_prefix":"3.5.140.0/22","region":"ap-northeast-2","service":"AMAZON"},
		{"ip_prefix":"3.5.140.0/22","region":"ap-northeast-2","service":"EC2"},
		{"ip_prefix":"52.0.0.0/11","region":"us-east-1","service":"AMAZON"}],
		"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/24","region":"GLOBAL","service":"AMAZON"}]}`)
	got, err := parseAWS(body)
	if err != nil {
		t.Fatal(err)
	}
	want := []RangeEntry{
		{netip.MustParsePrefix("3.5.140.0/22"), "EC2 · ap-northeast-2"},
		{netip.MustParsePrefix("52.0.0.0/11"), "AMAZON · us-east-1"},
		{netip.MustParsePrefix("2600:1f00::/24"), "AMAZON · GLOBAL"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}

func TestParseAzureUsesRegionTags(t *testing.T) {
	body := []byte(`{"values":[
		{"name":"AzureCloud","properties":{"region":"","addressPrefixes":["4.0.0.0/8"]}},
		{"name":"AzureCloud.eastus","properties":{"region":"eastus","addressPrefixes":["4.1.0.0/16"]}},
		{"name":"Storage.eastus","properties":{"region":"eastus","addressPrefixes":["4.1.2.0/24"]}}]}`)
	got, err := parseAzure(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Prefix.String() != "4.1.0.0/16" || got[0].Detail != "eastus" {
		t.Fatalf("%+v", got)
	}
}

func TestParseLinesAndCSV(t *testing.T) {
	got, err := parseLines([]byte("# comment\n\n185.220.101.1\n10.0.0.0/8\nnot an ip\n2001:db8::1\n"))
	if err != nil {
		t.Fatal(err)
	}
	var prefixes []string
	for _, e := range got {
		prefixes = append(prefixes, e.Prefix.String())
	}
	if strings.Join(prefixes, " ") != "185.220.101.1/32 10.0.0.0/8 2001:db8::1/128" {
		t.Fatalf("%v", prefixes)
	}
	do, err := parseDigitalOcean([]byte("5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XH\n"))
	if err != nil || len(do) != 1 || do[0].Detail != "Amsterdam · NL" {
		t.Fatalf("%+v %v", do, err)
	}
}

func TestAzureLinkFromPage(t *testing.T) {
	fetch := &mapFetch{bodies: map[string]string{
		"https://www.microsoft.com/en-us/download/details.aspx?id=56519":                   `<a href="https://download.microsoft.com/download/7/1/d/x/ServiceTags_Public_20260921.json">`,
		"https://download.microsoft.com/download/7/1/d/x/ServiceTags_Public_20260921.json": `{"values":[]}`,
	}}
	body, err := getAzure(context.Background(), fetch)
	if err != nil || !strings.Contains(string(body), "values") {
		t.Fatalf("%q %v", body, err)
	}
}

func TestMatchPicksMostSpecificPerList(t *testing.T) {
	set := RangeSet{Lists: []RangeList{
		{Source: RangeSource{Label: "AWS", Kind: KindHosting}, Entries: []RangeEntry{
			{netip.MustParsePrefix("52.0.0.0/11"), "AMAZON"},
			{netip.MustParsePrefix("52.1.0.0/16"), "EC2 · us-east-1"},
		}},
		{Source: RangeSource{Label: "Tor exit list", Kind: KindTor}, Entries: []RangeEntry{
			{netip.MustParsePrefix("52.1.2.3/32"), ""},
		}},
		{Source: RangeSource{Label: "Fastly", Kind: KindCDN}, Entries: []RangeEntry{
			{netip.MustParsePrefix("151.101.0.0/16"), ""},
		}},
	}}
	got := set.Match(netip.MustParseAddr("52.1.2.3"))
	want := []RangeFlag{
		{Kind: KindHosting, Source: "AWS", Prefix: "52.1.0.0/16", Detail: "EC2 · us-east-1"},
		{Kind: KindTor, Source: "Tor exit list", Prefix: "52.1.2.3/32"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}

type mapFetch struct {
	bodies map[string]string
	calls  []string
}

func (m *mapFetch) Get(ctx context.Context, url string) ([]byte, int, error) {
	m.calls = append(m.calls, url)
	body, ok := m.bodies[url]
	if !ok {
		return nil, 0, errors.New("offline")
	}
	return []byte(body), 200, nil
}

func testSource() RangeSource {
	return RangeSource{Name: "t", Label: "Test", Kind: KindHosting, MaxAge: time.Hour,
		get: getURL("https://lists.example/t"), parse: parseLines}
}

func TestRangeCache(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	writeAged := func(dir, body string, age time.Duration) {
		path := filepath.Join(dir, "t.cache")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	online := func() *mapFetch {
		return &mapFetch{bodies: map[string]string{"https://lists.example/t": "9.9.9.0/24\n"}}
	}

	t.Run("fresh cache is not refetched", func(t *testing.T) {
		dir := t.TempDir()
		writeAged(dir, "1.1.1.0/24\n", time.Minute)
		fetch := online()
		set := RangeCache{Dir: dir, Fetch: fetch, Update: true, Now: func() time.Time { return now }}.LoadRanges(context.Background(), []RangeSource{testSource()})
		if len(fetch.calls) != 0 || len(set.Lists) != 1 || set.Lists[0].Entries[0].Prefix.String() != "1.1.1.0/24" || len(set.Stale) != 0 {
			t.Fatalf("%+v %v", set, fetch.calls)
		}
	})
	t.Run("old cache is refreshed and rewritten", func(t *testing.T) {
		dir := t.TempDir()
		writeAged(dir, "1.1.1.0/24\n", 2*time.Hour)
		set := RangeCache{Dir: dir, Fetch: online(), Update: true, Now: func() time.Time { return now }}.LoadRanges(context.Background(), []RangeSource{testSource()})
		body, _ := os.ReadFile(filepath.Join(dir, "t.cache"))
		if set.Lists[0].Entries[0].Prefix.String() != "9.9.9.0/24" || len(set.Stale) != 0 || !strings.Contains(string(body), "9.9.9.0/24") {
			t.Fatalf("%+v %q", set, body)
		}
	})
	t.Run("failed refresh falls back to old copy", func(t *testing.T) {
		dir := t.TempDir()
		writeAged(dir, "1.1.1.0/24\n", 2*time.Hour)
		set := RangeCache{Dir: dir, Fetch: &mapFetch{}, Update: true, Now: func() time.Time { return now }}.LoadRanges(context.Background(), []RangeSource{testSource()})
		if len(set.Lists) != 1 || !reflect.DeepEqual(set.Stale, []string{"Test"}) || len(set.Unavailable) != 0 {
			t.Fatalf("%+v", set)
		}
	})
	t.Run("no copy and no network is unavailable", func(t *testing.T) {
		set := RangeCache{Dir: t.TempDir(), Fetch: &mapFetch{}, Update: true, Now: func() time.Time { return now }}.LoadRanges(context.Background(), []RangeSource{testSource()})
		if len(set.Lists) != 0 || !reflect.DeepEqual(set.Unavailable, []string{"Test"}) {
			t.Fatalf("%+v", set)
		}
	})
	t.Run("no-update never fetches", func(t *testing.T) {
		dir := t.TempDir()
		writeAged(dir, "1.1.1.0/24\n", 2*time.Hour)
		fetch := online()
		set := RangeCache{Dir: dir, Fetch: fetch, Update: false, Now: func() time.Time { return now }}.LoadRanges(context.Background(), []RangeSource{testSource()})
		if len(fetch.calls) != 0 || !reflect.DeepEqual(set.Stale, []string{"Test"}) {
			t.Fatalf("%+v %v", set, fetch.calls)
		}
	})
}

func TestRangesRow(t *testing.T) {
	list := RangeList{Source: RangeSource{Label: "Tor exit list", Kind: KindTor}, Entries: []RangeEntry{{netip.MustParsePrefix("185.220.101.1/32"), ""}}}
	run := func(set RangeSet, ip string) (Profile, checker.Result) {
		p, rows, err := Lookup(context.Background(), Sources{DNS: &fakeInfra{}, Ranges: &set}, ip)
		if err != nil {
			t.Fatal(err)
		}
		return p, rowBySite(rows, "ranges")
	}
	if p, row := run(RangeSet{Lists: []RangeList{list}}, "185.220.101.1"); row.Status != checker.StatusFound || len(p.Flags) != 1 || p.Flags[0].Kind != KindTor {
		t.Fatalf("%+v %+v", row, p)
	}
	if _, row := run(RangeSet{Lists: []RangeList{list}}, "8.8.8.8"); row.Status != checker.StatusNotFound {
		t.Fatalf("%+v", row)
	}
	// A list that could not be read turns a miss into an error.
	p, row := run(RangeSet{Lists: []RangeList{list}, Unavailable: []string{"Azure"}}, "8.8.8.8")
	if row.Status != checker.StatusError || !strings.Contains(row.Detail, "Azure") || !reflect.DeepEqual(p.RangesUnavailable, []string{"Azure"}) {
		t.Fatalf("%+v", row)
	}
	// A hit still stands when another list is missing.
	if _, row := run(RangeSet{Lists: []RangeList{list}, Unavailable: []string{"Azure"}}, "185.220.101.1"); row.Status != checker.StatusFound {
		t.Fatalf("%+v", row)
	}
	if _, row := run(RangeSet{}, "8.8.8.8"); row.Status != checker.StatusError {
		t.Fatalf("%+v", row)
	}
	if p, row := run(RangeSet{Lists: []RangeList{list}}, "10.0.0.1"); row.Status != checker.StatusNotFound || p.RangesChecked != 0 {
		t.Fatalf("%+v", row)
	}
}
