package entity

import (
	"context"
	"strings"
	"testing"

	"github.com/idrewlong/footprint/pkg/checker"
)

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
