package entity

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/mail"
	"strconv"
	"strings"

	"github.com/idrewlong/footprint/pkg/checker"
)

const secTickersURL = "https://www.sec.gov/files/company_tickers.json"

// Record is one OFAC SDN entry loaded from a local list.
type Record struct {
	Name, Type, Program string
}

// Ticker is one SEC company ticker row.
type Ticker struct {
	CIK    int
	Ticker string
	Title  string
}

// Fetcher is the HTTP surface SEC needs. Tests supply a fake.
type Fetcher interface {
	Get(ctx context.Context, url string) ([]byte, int, error)
}

// Validate rejects empty strings, emails, and IP addresses so callers
// do not treat those as organization names.
func Validate(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("organization name is empty")
	}
	if _, err := mail.ParseAddress(name); err == nil {
		return fmt.Errorf("organization name looks like an email address")
	}
	if net.ParseIP(name) != nil {
		return fmt.Errorf("organization name looks like an IP address")
	}
	return nil
}

// LoadSDN reads an OFAC SDN CSV. Headered files use ent_num; otherwise
// columns are positional (name, type, program at indices 1, 2, 3).
func LoadSDN(r io.Reader) ([]Record, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read SDN csv: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	nameIdx, typeIdx, progIdx := 1, 2, 3
	start := 0
	if len(rows[0]) > 0 && rows[0][0] == "ent_num" {
		start = 1
		nameIdx = indexOf(rows[0], "SDN_Name")
		typeIdx = indexOf(rows[0], "SDN_Type")
		progIdx = indexOf(rows[0], "Program")
		if nameIdx < 0 || typeIdx < 0 || progIdx < 0 {
			return nil, fmt.Errorf("SDN csv missing required headers")
		}
	}

	out := make([]Record, 0, len(rows)-start)
	for _, row := range rows[start:] {
		name := fieldAt(row, nameIdx)
		if name == "" {
			continue
		}
		out = append(out, Record{
			Name:    name,
			Type:    fieldAt(row, typeIdx),
			Program: fieldAt(row, progIdx),
		})
	}
	return out, nil
}

// Screen matches a name against a local OFAC SDN list. A nil list is an
// error; an empty loaded list with no match is not_found.
func Screen(name string, records []Record) checker.Result {
	row := checker.Result{
		Site:     "ofac",
		Domain:   name,
		Category: "entity",
		Method:   "entity",
	}
	if records == nil {
		row.Status = checker.StatusError
		row.Detail = "sanctions list not configured"
		return row
	}
	key := normalizeName(name)
	for _, rec := range records {
		if normalizeName(rec.Name) != key {
			continue
		}
		row.Status = checker.StatusFound
		row.Evidence = fmt.Sprintf("Local OFAC SDN list matches this name as %s, program %s.", rec.Name, rec.Program)
		return row
	}
	row.Status = checker.StatusNotFound
	row.Evidence = "Local OFAC SDN list has no exact match for this name."
	return row
}

// ParseTickers reads the SEC company_tickers.json object map.
func ParseTickers(r io.Reader) ([]Ticker, error) {
	var raw map[string]struct {
		CIK    json.Number `json:"cik_str"`
		Ticker string      `json:"ticker"`
		Title  string      `json:"title"`
	}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse SEC tickers: %w", err)
	}
	out := make([]Ticker, 0, len(raw))
	for _, item := range raw {
		cik, err := strconv.Atoi(item.CIK.String())
		if err != nil {
			return nil, fmt.Errorf("parse SEC CIK: %w", err)
		}
		out = append(out, Ticker{
			CIK:    cik,
			Ticker: item.Ticker,
			Title:  item.Title,
		})
	}
	return out, nil
}

// MatchTickers hits when the normalized query equals a normalized title or ticker.
func MatchTickers(name string, tickers []Ticker) checker.Result {
	row := checker.Result{
		Site:     "sec",
		Domain:   name,
		Category: "entity",
		Method:   "entity",
	}
	key := normalizeName(name)
	for _, t := range tickers {
		if normalizeName(t.Title) != key && normalizeName(t.Ticker) != key {
			continue
		}
		row.Status = checker.StatusFound
		row.Evidence = fmt.Sprintf("SEC company tickers list matches this name as %s (%s), CIK %d.", t.Title, t.Ticker, t.CIK)
		return row
	}
	row.Status = checker.StatusNotFound
	row.Evidence = "SEC company tickers list has no exact match for this name."
	return row
}

// SEC fetches company_tickers.json and matches the name. Transport errors
// and non-200 responses (except 429) are error with empty evidence.
func SEC(ctx context.Context, fetch Fetcher, name string) checker.Result {
	row := checker.Result{
		Site:     "sec",
		Domain:   name,
		Category: "entity",
		Method:   "entity",
	}
	if fetch == nil {
		row.Status = checker.StatusError
		return row
	}
	body, status, err := fetch.Get(ctx, secTickersURL)
	if err != nil {
		row.Status = checker.StatusError
		return row
	}
	switch status {
	case 429:
		row.Status = checker.StatusRateLimited
		return row
	case 200:
		tickers, err := ParseTickers(bytes.NewReader(body))
		if err != nil {
			row.Status = checker.StatusError
			return row
		}
		return MatchTickers(name, tickers)
	default:
		row.Status = checker.StatusError
		return row
	}
}

func normalizeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func indexOf(headers []string, name string) int {
	for i, h := range headers {
		if h == name {
			return i
		}
	}
	return -1
}

func fieldAt(row []string, i int) string {
	if i < 0 || i >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[i])
}
