// Package report renders a finished scan as JSON, a terminal report, or Markdown.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
)

// Summary counts each status so a partial run is not described as complete.
type Summary struct {
	Found       int `json:"found"`
	NotFound    int `json:"not_found"`
	RateLimited int `json:"rate_limited"`
	Error       int `json:"error"`
}

// Document is the machine-readable scan report.
type Document struct {
	Email    string           `json:"email,omitempty"`
	Username string           `json:"username,omitempty"`
	Summary  Summary          `json:"summary"`
	Results  []checker.Result `json:"results"`
}

// Build summarizes results. onlyFound drops every row that is not a hit
// from Results; Summary still counts the full run.
func Build(email string, results []checker.Result, onlyFound bool) Document {
	doc := Document{
		Email:   email,
		Summary: Summarize(results),
		Results: append([]checker.Result(nil), results...),
	}
	sort.Slice(doc.Results, func(i, j int) bool {
		return doc.Results[i].Site < doc.Results[j].Site
	})
	if onlyFound {
		kept := doc.Results[:0]
		for _, res := range doc.Results {
			if res.Status == checker.StatusFound {
				kept = append(kept, res)
			}
		}
		doc.Results = kept
	}
	return doc
}

// BuildUser summarizes a username check. Summary still counts the full run.
func BuildUser(username string, results []checker.Result, onlyFound bool) Document {
	doc := Build("", results, onlyFound)
	doc.Email = ""
	doc.Username = username
	return doc
}

// Summarize counts statuses. An unrecognized status is an error so it
// cannot disappear from the totals.
func Summarize(results []checker.Result) Summary {
	var sum Summary
	for _, res := range results {
		switch res.Status {
		case checker.StatusFound:
			sum.Found++
		case checker.StatusNotFound:
			sum.NotFound++
		case checker.StatusRateLimited:
			sum.RateLimited++
		default:
			sum.Error++
		}
	}
	return sum
}

const humanWidth = 72

// WriteHuman writes the terminal report. The summary is first. Each hit is a
// short block with one action link. Rate-limited and errored sites are named.
// Misses stay in the summary. color paints the report when stdout is a terminal.
func WriteHuman(w io.Writer, doc Document, elapsed time.Duration, color bool) error {
	query := doc.Email
	empty := "No accounts found."
	switch {
	case doc.Email != "" && doc.Username != "":
		query = doc.Email + " · " + doc.Username
		empty = "No accounts or profiles found."
	case doc.Username != "":
		query = doc.Username
		empty = "No profiles found."
	}
	var found, limited, failed []checker.Result
	for _, res := range doc.Results {
		switch res.Status {
		case checker.StatusFound:
			found = append(found, res)
		case checker.StatusNotFound:
			// Misses stay in the summary.
		case checker.StatusRateLimited:
			limited = append(limited, res)
		default:
			failed = append(failed, res)
		}
	}
	bySite := func(rows []checker.Result) {
		sort.Slice(rows, func(i, j int) bool { return rows[i].Site < rows[j].Site })
	}
	bySite(found)
	bySite(limited)
	bySite(failed)
	problems := append(append([]checker.Result{}, limited...), failed...)

	var b strings.Builder
	b.WriteString(headerLine(query, elapsed, color))
	b.WriteByte('\n')
	b.WriteString(summaryLine(doc.Summary, color))
	b.WriteByte('\n')
	if len(found) == 0 {
		b.WriteString("\n")
		b.WriteString(empty)
		b.WriteByte('\n')
	} else {
		b.WriteByte('\n')
		writeRule(&b, "found", "1;32", color)
		writeFoundBlocks(&b, found, color)
	}
	if len(problems) > 0 {
		b.WriteByte('\n')
		writeRule(&b, "couldn't check", "1;33", color)
		writeProblemLines(&b, problems, color)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func headerLine(query string, elapsed time.Duration, color bool) string {
	right := formatDuration(elapsed)
	gap := humanWidth - len(query) - len(right)
	if gap < 2 {
		gap = 2
	}
	left := query
	if color {
		left = colorize("1", query)
		right = colorize("2", right)
	}
	return left + strings.Repeat(" ", gap) + right
}

type segment struct {
	text string
	code string
}

func writeRule(b *strings.Builder, title, code string, color bool) {
	dashes := humanWidth - len(title) - 1
	if dashes < 4 {
		dashes = 4
	}
	rule := strings.Repeat("─", dashes)
	if color {
		b.WriteString(colorize(code, title))
		b.WriteByte(' ')
		b.WriteString(colorize("2", rule))
	} else {
		b.WriteString(title)
		b.WriteByte(' ')
		b.WriteString(rule)
	}
	b.WriteByte('\n')
}

func writeFoundBlocks(b *strings.Builder, rows []checker.Result, color bool) {
	siteW := 0
	for _, res := range rows {
		if n := len(res.Site); n > siteW {
			siteW = n
		}
	}
	for i, res := range rows {
		if i > 0 {
			b.WriteByte('\n')
		}
		bullet := "●"
		name := res.Site + strings.Repeat(" ", siteW-len(res.Site))
		category := res.Category
		if color {
			bullet = colorize("1;32", "●")
			name = colorize("1", res.Site) + strings.Repeat(" ", siteW-len(res.Site))
			category = colorize("2", res.Category)
		}
		fmt.Fprintf(b, "  %s  %s  %s\n", bullet, name, category)
		for _, line := range actionLines(res) {
			text := line.text
			if color && line.code != "" {
				text = colorize(line.code, line.text)
			}
			fmt.Fprintf(b, "     %s\n", text)
		}
	}
}

func actionLines(res checker.Result) []segment {
	if res.Method == "breach" {
		return breachLines(res.Detail)
	}
	var lines []segment
	switch {
	case res.ProfileURL != "":
		lines = append(lines, segment{text: res.ProfileURL, code: "4;36"})
		if res.Detail != "" {
			lines = append(lines, segment{text: oneLine(res.Detail, 80), code: "2"})
		}
	case res.DeleteURL != "":
		lines = append(lines, segment{text: res.DeleteURL, code: "4;36"})
	case res.SecurityURL != "":
		lines = append(lines, segment{text: res.SecurityURL, code: "4;36"})
	default:
		if res.Detail != "" {
			lines = append(lines, segment{text: oneLine(res.Detail, 80), code: "2"})
		}
	}
	return lines
}

func writeProblemLines(b *strings.Builder, rows []checker.Result, color bool) {
	siteW, labelW := 0, 0
	labels := make([]string, len(rows))
	codes := make([]string, len(rows))
	for i, res := range rows {
		label, code := "error", "1;31"
		if res.Status == checker.StatusRateLimited {
			label, code = "rate limited", "1;33"
		}
		labels[i], codes[i] = label, code
		if n := len(res.Site); n > siteW {
			siteW = n
		}
		if n := len(label); n > labelW {
			labelW = n
		}
	}
	for i, res := range rows {
		bullet := "●"
		name := res.Site + strings.Repeat(" ", siteW-len(res.Site))
		label := labels[i] + strings.Repeat(" ", labelW-len(labels[i]))
		if color {
			bullet = colorize(codes[i], "●")
			name = colorize("1", res.Site) + strings.Repeat(" ", siteW-len(res.Site))
			label = colorize(codes[i], labels[i]) + strings.Repeat(" ", labelW-len(labels[i]))
		}
		fmt.Fprintf(b, "  %s  %s  %s", bullet, name, label)
		detail := oneLine(res.Detail, 80)
		if detail != "" && !strings.EqualFold(detail, labels[i]) {
			if color {
				detail = colorize("2", detail)
			}
			fmt.Fprintf(b, "  %s", detail)
		}
		b.WriteByte('\n')
	}
}

func breachLines(detail string) []segment {
	detail = strings.Join(strings.Fields(detail), " ")
	if detail == "" {
		return nil
	}
	var lines []segment
	for _, name := range strings.Split(detail, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		lines = append(lines, segment{text: name})
	}
	return lines
}

func colorize(code, text string) string {
	if code == "" || text == "" {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

// WriteJSON writes an indented document. URLs are not escaped.
func WriteJSON(w io.Writer, doc Document) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// WriteMarkdown writes every status in the document. Found accounts keep
// their delete and security links. Other statuses are listed by name.
func WriteMarkdown(w io.Writer, doc Document, elapsed time.Duration) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Footprint\n\n")
	if doc.Email != "" {
		fmt.Fprintf(&b, "Email: `%s`\n\n", strings.ReplaceAll(doc.Email, "`", "'"))
	}
	if doc.Username != "" {
		fmt.Fprintf(&b, "Username: `%s`\n\n", strings.ReplaceAll(doc.Username, "`", "'"))
	}
	fmt.Fprintf(&b, "| Status | Count |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| Found | %d |\n", doc.Summary.Found)
	fmt.Fprintf(&b, "| Not found | %d |\n", doc.Summary.NotFound)
	fmt.Fprintf(&b, "| Rate limited | %d |\n", doc.Summary.RateLimited)
	fmt.Fprintf(&b, "| Error | %d |\n\n", doc.Summary.Error)
	fmt.Fprintf(&b, "Checked in %s.\n\n", formatDuration(elapsed))

	var found, notFound, limited, failed []checker.Result
	for _, res := range doc.Results {
		switch res.Status {
		case checker.StatusFound:
			found = append(found, res)
		case checker.StatusNotFound:
			notFound = append(notFound, res)
		case checker.StatusRateLimited:
			limited = append(limited, res)
		default:
			failed = append(failed, res)
		}
	}
	b.WriteString("## Found\n\n")
	if len(found) == 0 {
		switch {
		case doc.Email != "" && doc.Username != "":
			b.WriteString("No accounts or profiles found.\n\n")
		case doc.Username != "":
			b.WriteString("No profiles found.\n\n")
		default:
			b.WriteString("No accounts found.\n\n")
		}
	}
	for _, res := range found {
		fmt.Fprintf(&b, "### %s\n\n", res.Site)
		fmt.Fprintf(&b, "- Domain: %s\n", res.Domain)
		fmt.Fprintf(&b, "- Category: %s\n", res.Category)
		fmt.Fprintf(&b, "- Method: %s\n", res.Method)
		if res.DeleteURL != "" {
			fmt.Fprintf(&b, "- Delete: %s\n", res.DeleteURL)
		}
		if res.SecurityURL != "" {
			fmt.Fprintf(&b, "- Security: %s\n", res.SecurityURL)
		}
		if res.ProfileURL != "" {
			fmt.Fprintf(&b, "- Profile: %s\n", res.ProfileURL)
		}
		if res.Detail != "" {
			fmt.Fprintf(&b, "- Detail: %s\n", res.Detail)
		}
		b.WriteString("\n")
	}
	writeStatusSection(&b, "Not found", notFound)
	writeStatusSection(&b, "Rate limited", limited)
	writeStatusSection(&b, "Error", failed)
	_, err := io.WriteString(w, b.String())
	return err
}

func writeStatusSection(b *strings.Builder, title string, rows []checker.Result) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(rows) == 0 {
		b.WriteString("None.\n\n")
		return
	}
	for _, res := range rows {
		fmt.Fprintf(b, "- **%s**", res.Site)
		if res.Domain != "" {
			fmt.Fprintf(b, " (%s)", res.Domain)
		}
		if res.Detail != "" {
			fmt.Fprintf(b, ": %s", res.Detail)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func summaryLine(sum Summary, color bool) string {
	parts := []struct {
		text string
		code string
	}{
		{fmt.Sprintf("%d found", sum.Found), "1;32"},
		{fmt.Sprintf("%d not found", sum.NotFound), "2"},
		{fmt.Sprintf("%d rate limited", sum.RateLimited), "1;33"},
		{fmt.Sprintf("%d error", sum.Error), "1;31"},
	}
	var b strings.Builder
	for i, part := range parts {
		if i > 0 {
			b.WriteString(" · ")
		}
		if color {
			b.WriteString(colorize(part.code, part.text))
			continue
		}
		b.WriteString(part.text)
	}
	return b.String()
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Millisecond)
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if max > 0 && len(s) > max {
		return s[:max-1] + "…"
	}
	return s
}
