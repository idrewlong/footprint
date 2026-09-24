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
	"github.com/idrewlong/footprint/pkg/infra"
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
	Email         string           `json:"email,omitempty"`
	Username      string           `json:"username,omitempty"`
	SubjectDomain string           `json:"subject_domain,omitempty"`
	SubjectIP     string           `json:"subject_ip,omitempty"`
	SubjectEntity string           `json:"subject_entity,omitempty"`
	IP            *infra.Profile   `json:"ip,omitempty"`
	Summary       Summary          `json:"summary"`
	Results       []checker.Result `json:"results"`
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

// ScoreConfidence stamps a confidence level on every found row in the
// document, using whether a profile username came from the mailbox. It is
// idempotent and safe to call before rendering or saving.
func ScoreConfidence(doc *Document) {
	if doc == nil {
		return
	}
	fromMailbox := usernameFromMailbox(doc.Email, doc.Username)
	for i := range doc.Results {
		doc.Results[i].Confidence = checker.Confidence(
			doc.Results[i].Method, doc.Results[i].Status, fromMailbox)
	}
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
	case doc.Email != "":
		// query already set from Email
	case doc.SubjectDomain != "":
		query = doc.SubjectDomain
		empty = "No domain records found."
	case doc.SubjectIP != "":
		query = doc.SubjectIP
		empty = "No network details found."
	case doc.SubjectEntity != "":
		query = doc.SubjectEntity
		empty = "No public-list match found."
	}
	panel := ipPanel(doc.IP)
	var found, limited, failed []checker.Result
	for _, res := range doc.Results {
		switch res.Status {
		case checker.StatusFound:
			// The IP panel already shows what the infra rows found.
			if len(panel) > 0 && res.Method == "infra" {
				continue
			}
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
	fromMailbox := usernameFromMailbox(doc.Email, doc.Username)

	var b strings.Builder
	b.WriteString(headerLine(query, elapsed, color))
	b.WriteByte('\n')
	b.WriteString(summaryLine(doc.Summary, color))
	b.WriteByte('\n')
	if len(panel) > 0 {
		b.WriteByte('\n')
		writeRule(&b, "ip address", "1;36", color)
		writeIPPanel(&b, panel, doc.IP, color)
	}
	if len(found) == 0 && len(panel) > 0 {
		// The panel is the finding.
	} else if len(found) == 0 {
		b.WriteString("\n")
		b.WriteString(empty)
		b.WriteByte('\n')
	} else {
		b.WriteByte('\n')
		writeRule(&b, "found", "1;32", color)
		writeFoundBlocks(&b, found, color, fromMailbox)
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

func writeFoundBlocks(b *strings.Builder, rows []checker.Result, color bool, fromMailbox bool) {
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
		if line := methodEvidence(res, fromMailbox, color); line != "" {
			fmt.Fprintf(b, "     %s\n", line)
		}
		for _, line := range actionLines(res) {
			text := line.text
			if color && line.code != "" {
				text = colorize(line.code, line.text)
			}
			fmt.Fprintf(b, "     %s\n", text)
		}
	}
}

func methodEvidence(res checker.Result, fromMailbox, color bool) string {
	sentence := evidenceSentence(res, fromMailbox)
	if res.Method == "" && sentence == "" {
		return ""
	}
	method := res.Method
	if color && method != "" {
		method = colorize("1", res.Method)
	}
	if sentence == "" {
		return method
	}
	if color {
		sentence = colorize("2", sentence)
	}
	if method == "" {
		return sentence
	}
	return method + " · " + sentence
}

func evidenceSentence(res checker.Result, fromMailbox bool) string {
	sentence := strings.TrimSpace(res.Evidence)
	if sentence == "" || res.Method != "profile" || !fromMailbox {
		return sentence
	}
	if !strings.HasSuffix(sentence, ".") {
		sentence += "."
	}
	return sentence + " Weaker than an email match: the username was taken from the mailbox."
}

func usernameFromMailbox(email, username string) bool {
	local, _, ok := strings.Cut(strings.TrimSpace(email), "@")
	if !ok || strings.TrimSpace(username) == "" {
		return false
	}
	return strings.EqualFold(local, strings.TrimSpace(username))
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

// Meta is the run stamp printed in the markdown case note.
type Meta struct {
	Version string
	RanAt   time.Time
	Elapsed time.Duration
}

// WriteMarkdown writes a one-page case note: a bottom line, findings
// strongest first, coverage, and actions. Rate-limited and error rows
// stay listed as unchecked. Misses stay in the counts.
func WriteMarkdown(w io.Writer, doc Document, meta Meta) error {
	var b strings.Builder
	b.WriteString("# Footprint\n\n")
	fmt.Fprintf(&b, "**Bottom line:** %s\n\n", bottomLine(doc))
	writeFindings(&b, doc)
	writeBreachTimeline(&b, doc)
	writeGrouped(&b, doc, "dns", "Domain")
	if rows := ipPanel(doc.IP); len(rows) > 0 {
		writeIPTable(&b, rows, doc.IP)
	} else {
		writeGrouped(&b, doc, "infra", "Infrastructure")
	}
	writeGrouped(&b, doc, "entity", "Entity")
	writeCoverage(&b, doc, meta)
	writeActions(&b, doc)
	_, err := io.WriteString(w, b.String())
	return err
}

// writeBreachTimeline lists breaches oldest first when any breach hit
// carries a date. Dates are breach metadata, not stolen values. Breaches
// with no date follow the dated ones. Nothing is written when no breach
// carried a date, since an unordered list adds nothing over the findings.
func writeBreachTimeline(b *strings.Builder, doc Document) {
	type hit struct{ name, date string }
	byName := map[string]hit{}
	var order []string
	anyDate := false
	for _, res := range doc.Results {
		if res.Status != checker.StatusFound || res.Method != "breach" {
			continue
		}
		for _, h := range res.Breaches {
			name := strings.TrimSpace(h.Name)
			if name == "" {
				continue
			}
			key := normalizeName(name)
			existing, ok := byName[key]
			if !ok {
				order = append(order, key)
				byName[key] = hit{name: name, date: strings.TrimSpace(h.Date)}
			} else if existing.date == "" && strings.TrimSpace(h.Date) != "" {
				existing.date = strings.TrimSpace(h.Date)
				byName[key] = existing
			}
			if strings.TrimSpace(h.Date) != "" {
				anyDate = true
			}
		}
	}
	if !anyDate {
		return
	}
	hits := make([]hit, 0, len(order))
	for _, key := range order {
		hits = append(hits, byName[key])
	}
	// Dated first, ascending by the source's date string (YYYY-MM sorts
	// correctly as text); undated last, by name.
	sort.SliceStable(hits, func(i, j int) bool {
		di, dj := hits[i].date, hits[j].date
		if (di == "") != (dj == "") {
			return di != ""
		}
		if di != dj {
			return di < dj
		}
		return hits[i].name < hits[j].name
	})
	b.WriteString("## Breach timeline\n\n")
	for _, h := range hits {
		when := h.date
		if when == "" {
			when = "date unknown"
		}
		fmt.Fprintf(b, "- %s — %s\n", when, mdCell(h.name))
	}
	b.WriteString("\n")
}

func bottomLine(doc Document) string {
	var emailHits, breaches, profiles, dnsHits, infraHits, entityHits int
	for _, res := range doc.Results {
		if res.Status != checker.StatusFound {
			continue
		}
		switch res.Method {
		case "register", "login", "password_reset":
			emailHits++
		case "breach":
			breaches++
		case "profile":
			profiles++
		case "dns":
			dnsHits++
		case "infra":
			infraHits++
		case "entity":
			entityHits++
		}
	}
	unchecked := doc.Summary.RateLimited + doc.Summary.Error
	fromMailbox := usernameFromMailbox(doc.Email, doc.Username)
	var parts []string
	if doc.Email != "" {
		lead := []string{}
		if emailHits == 0 && breaches == 0 {
			lead = append(lead, "No email matches")
		} else {
			if emailHits > 0 {
				lead = append(lead, countPhrase(emailHits, "email match", "email matches"))
			}
			if breaches > 0 {
				lead = append(lead, countPhrase(breaches, "breach", "breaches"))
			}
		}
		parts = append(parts, strings.Join(lead, " and ")+" for "+codeSpan(doc.Email))
	}
	if doc.Username != "" && (doc.Email == "" || profiles > 0) {
		phrase := countPhrase(profiles, "public profile", "public profiles")
		if doc.Email == "" && profiles == 0 {
			phrase = "No public profiles"
		}
		clause := phrase + " for " + codeSpan(doc.Username)
		if fromMailbox && profiles > 0 {
			clause += " (weaker than an email match; the username was taken from the mailbox)"
		}
		parts = append(parts, clause)
	}
	if doc.Email == "" && doc.Username == "" {
		switch {
		case doc.SubjectDomain != "":
			parts = append(parts, subjectNotes(dnsHits, "domain note", "domain notes", "Domain notes", doc.SubjectDomain))
		case doc.SubjectIP != "":
			parts = append(parts, subjectNotes(infraHits, "network note", "network notes", "Network notes", doc.SubjectIP))
		case doc.SubjectEntity != "":
			parts = append(parts, subjectNotes(entityHits, "entity note", "entity notes", "Entity notes", doc.SubjectEntity))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "No findings")
	}
	line := parts[0]
	if len(parts) == 2 {
		line = parts[0] + ", and " + parts[1]
	}
	if unchecked > 0 {
		line += ". " + countPhrase(unchecked, "check was", "checks were") + " not completed"
	}
	return line + "."
}

func subjectNotes(n int, one, many, zeroLead, subject string) string {
	if n == 0 {
		return zeroLead + " for " + codeSpan(subject)
	}
	return countPhrase(n, one, many) + " for " + codeSpan(subject)
}

func writeFindings(b *strings.Builder, doc Document) {
	found := findingsRows(doc.Results)
	if len(found) == 0 {
		if doc.Email == "" && doc.Username == "" {
			return
		}
		b.WriteString("## Findings\n\n")
		switch {
		case doc.Email != "" && doc.Username != "":
			b.WriteString("No accounts or profiles found.\n\n")
		case doc.Username != "":
			b.WriteString("No profiles found.\n\n")
		default:
			b.WriteString("No accounts found.\n\n")
		}
		return
	}
	b.WriteString("## Findings\n\n")
	fromMailbox := usernameFromMailbox(doc.Email, doc.Username)
	sort.SliceStable(found, func(i, j int) bool {
		si, sj := findingRank(found[i], fromMailbox), findingRank(found[j], fromMailbox)
		if si != sj {
			return si < sj
		}
		return found[i].Site < found[j].Site
	})
	b.WriteString("| Site | Method | Confidence | Evidence |\n| --- | --- | --- | --- |\n")
	for _, res := range found {
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", mdCell(res.Site), mdCell(res.Method), mdCell(confidenceLabel(res, fromMailbox)), mdCell(findingEvidence(res, fromMailbox)))
	}
	b.WriteString("\n")
}

// confidenceLabel is the level for a row, computed on demand so markdown
// rendering does not depend on ScoreConfidence having been called first.
func confidenceLabel(res checker.Result, fromMailbox bool) string {
	if res.Confidence != "" {
		return res.Confidence
	}
	return checker.Confidence(res.Method, res.Status, fromMailbox)
}

func writeGrouped(b *strings.Builder, doc Document, method, title string) {
	var rows []checker.Result
	for _, res := range doc.Results {
		if res.Status == checker.StatusFound && res.Method == method {
			rows = append(rows, res)
		}
	}
	if len(rows) == 0 {
		return
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Site < rows[j].Site })
	fmt.Fprintf(b, "## %s\n\n", title)
	b.WriteString("| Site | Method | Evidence |\n| --- | --- | --- |\n")
	for _, res := range rows {
		fmt.Fprintf(b, "| %s | %s | %s |\n", mdCell(res.Site), mdCell(res.Method), mdCell(findingEvidence(res, false)))
	}
	b.WriteString("\n")
}

func findingsRows(results []checker.Result) []checker.Result {
	var found []checker.Result
	for _, res := range results {
		if res.Status != checker.StatusFound {
			continue
		}
		switch res.Method {
		case "register", "login", "password_reset", "breach", "profile":
			found = append(found, res)
		}
	}
	return found
}

func findingEvidence(res checker.Result, fromMailbox bool) string {
	sentence := evidenceSentence(res, fromMailbox)
	if res.ProfileURL == "" {
		return sentence
	}
	if sentence == "" {
		return res.ProfileURL
	}
	return sentence + " " + res.ProfileURL
}

func findingRank(res checker.Result, fromMailbox bool) int {
	switch res.Method {
	case "register", "login", "password_reset":
		return 0
	case "breach":
		return 1
	case "profile":
		if fromMailbox {
			return 3
		}
		return 2
	default:
		return 4
	}
}

func writeCoverage(b *strings.Builder, doc Document, meta Meta) {
	b.WriteString("## Coverage\n\n")
	fmt.Fprintf(b, "%d found, %d not found, %d rate limited, %d error.\n\n",
		doc.Summary.Found, doc.Summary.NotFound, doc.Summary.RateLimited, doc.Summary.Error)
	version := meta.Version
	if strings.TrimSpace(version) == "" {
		version = "dev"
	}
	when := "unknown time"
	if !meta.RanAt.IsZero() {
		when = meta.RanAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	fmt.Fprintf(b, "footprint %s · %s · %s\n\n", version, when, formatDuration(meta.Elapsed))
	b.WriteString("Unchecked:\n\n")
	var limited, failed []checker.Result
	for _, res := range doc.Results {
		switch res.Status {
		case checker.StatusRateLimited:
			limited = append(limited, res)
		case checker.StatusFound, checker.StatusNotFound:
		default:
			failed = append(failed, res)
		}
	}
	sort.Slice(limited, func(i, j int) bool { return limited[i].Site < limited[j].Site })
	sort.Slice(failed, func(i, j int) bool { return failed[i].Site < failed[j].Site })
	if len(limited) == 0 && len(failed) == 0 {
		if doc.Summary.RateLimited+doc.Summary.Error == 0 {
			b.WriteString("None.\n\n")
		} else {
			b.WriteString("Names were not included in this export.\n\n")
		}
		return
	}
	for _, res := range limited {
		fmt.Fprintf(b, "- **%s** — rate limited\n", res.Site)
	}
	for _, res := range failed {
		fmt.Fprintf(b, "- **%s** — error", res.Site)
		if detail := oneLine(res.Detail, 0); detail != "" {
			fmt.Fprintf(b, ". %s", detail)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func writeActions(b *strings.Builder, doc Document) {
	b.WriteString("## Actions\n\n")
	names := breachNames(doc.Results)
	var rows []checker.Result
	for _, res := range doc.Results {
		if res.Status != checker.StatusFound {
			continue
		}
		if res.DeleteURL == "" && res.SecurityURL == "" {
			continue
		}
		rows = append(rows, res)
	}
	if len(rows) == 0 {
		b.WriteString("None.\n")
		return
	}
	sort.SliceStable(rows, func(i, j int) bool {
		mi := len(matchingBreaches(rows[i].Site, names)) > 0
		mj := len(matchingBreaches(rows[j].Site, names)) > 0
		if mi != mj {
			return mi
		}
		return rows[i].Site < rows[j].Site
	})
	for _, res := range rows {
		matched := matchingBreaches(res.Site, names)
		fmt.Fprintf(b, "- **%s**", res.Site)
		if len(matched) > 0 {
			fmt.Fprintf(b, " — Change the password and turn on 2FA. This address appears in the %s.", breachNote(matched))
		}
		b.WriteString("\n")
		if res.SecurityURL != "" {
			fmt.Fprintf(b, "  - Security: %s\n", res.SecurityURL)
		}
		if res.DeleteURL != "" {
			fmt.Fprintf(b, "  - Delete: %s\n", res.DeleteURL)
		}
	}
}

func breachNames(results []checker.Result) []string {
	var names []string
	seen := map[string]struct{}{}
	for _, res := range results {
		if res.Status != checker.StatusFound || res.Method != "breach" {
			continue
		}
		for _, name := range strings.Split(res.Detail, ",") {
			name = strings.TrimSpace(name)
			key := normalizeName(name)
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			names = append(names, name)
		}
	}
	return names
}

func matchingBreaches(site string, names []string) []string {
	key := normalizeName(site)
	var matched []string
	for _, name := range names {
		if normalizeName(name) == key {
			matched = append(matched, name)
		}
	}
	return matched
}

func breachNote(names []string) string {
	if len(names) == 1 {
		return names[0] + " breach"
	}
	return humanList(names) + " breaches"
}

func humanList(names []string) string {
	if len(names) == 2 {
		return names[0] + " and " + names[1]
	}
	return strings.Join(names[:len(names)-1], ", ") + ", and " + names[len(names)-1]
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

func codeSpan(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "'") + "`"
}

func mdCell(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(s, "|", "\\|")
}

func countPhrase(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
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

// ipField is one labeled line of the IP panel.
type ipField struct{ label, value string }

// ipPanel lists the profile fields that have values, in the order a
// what-is-my-IP page shows them. A nil profile has no panel.
func ipPanel(p *infra.Profile) []ipField {
	if p == nil || p.IP == "" {
		return nil
	}
	scope := "public"
	if !p.Public {
		scope = "private or reserved, not sent to public lookups"
	}
	country := p.Country
	switch {
	case country != "" && p.CountryCode != "":
		country += " (" + p.CountryCode + ")"
	case country == "":
		country = p.CountryCode
	}
	asn := ""
	if p.ASN != "" {
		asn = joinNonEmpty(" · ", "AS"+p.ASN, p.ASName)
	}
	network := joinNonEmpty(" · ", p.Network, p.NetworkHandle, p.NetworkRange)
	coords := ""
	if p.Latitude != nil && p.Longitude != nil && p.AccuracyKM > 0 {
		coords = fmt.Sprintf("%.4f, %.4f ±%d km", *p.Latitude, *p.Longitude, p.AccuracyKM)
	}
	hostname := p.Hostname
	switch {
	case hostname == "":
	case p.HostnameCheck == "confirmed":
		hostname += " · resolves back to this IP"
	case p.HostnameCheck == "mismatch":
		hostname += " · does not resolve back to this IP"
	}
	all := []ipField{
		{"IP", p.IP + " · " + p.Version + " · " + scope},
		{"Hostname", hostname},
		{"City", p.City},
		{"Region", p.Region},
		{"Postal code", p.PostalCode},
		{"Country", country},
		{"Time zone", p.TimeZone},
		{"Coordinates", coords},
		{"ASN", asn},
		{"Prefix", joinNonEmpty(" · ", p.Prefix, p.Registry)},
		{"Network", network},
		{"Organization", p.Organization},
	}
	all = append(all, flagFields(p)...)
	rows := all[:0]
	for _, f := range all {
		if f.value != "" {
			rows = append(rows, f)
		}
	}
	return rows
}

var flagKinds = map[string]string{
	infra.KindHosting: "Cloud or hosting",
	infra.KindCDN:     "CDN",
	infra.KindTor:     "Tor exit",
	infra.KindVPN:     "VPN (community list)",
}

// flagFields is one line per list that contains the address, or one line
// saying none did. Lists that could not be read are named, so a miss is
// never shown as complete when it is not.
func flagFields(p *infra.Profile) []ipField {
	if p.RangesChecked == 0 && len(p.RangesUnavailable) == 0 {
		return nil
	}
	var out []ipField
	for i, f := range p.Flags {
		label := ""
		if i == 0 {
			label = "Flags"
		}
		kind := flagKinds[f.Kind]
		if kind == "" {
			kind = f.Kind
		}
		out = append(out, ipField{label, joinNonEmpty(" · ", kind, f.Source, f.Detail, f.Prefix)})
	}
	if len(p.Flags) == 0 {
		value := fmt.Sprintf("none in %d published lists", p.RangesChecked)
		if len(p.RangesUnavailable) > 0 {
			value = fmt.Sprintf("none in %d lists read", p.RangesChecked)
		}
		out = append(out, ipField{"Flags", value})
	}
	var notes []string
	if len(p.RangesUnavailable) > 0 {
		notes = append(notes, "could not load "+strings.Join(p.RangesUnavailable, ", "))
	}
	if len(p.RangesStale) > 0 {
		notes = append(notes, "old copy of "+strings.Join(p.RangesStale, ", "))
	}
	if len(notes) > 0 {
		out = append(out, ipField{"Range lists", strings.Join(notes, "; ")})
	}
	return out
}

func joinNonEmpty(sep string, parts ...string) string {
	kept := parts[:0:0]
	for _, part := range parts {
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, sep)
}

const ipLocationNote = "Location is the network's, not a person's or a street address."

func hasLocation(p *infra.Profile) bool {
	return p.City != "" || p.Region != "" || p.Latitude != nil || p.PostalCode != "" || p.Country != "" || p.CountryCode != ""
}

func writeIPPanel(b *strings.Builder, rows []ipField, p *infra.Profile, color bool) {
	labelW := 0
	for _, f := range rows {
		if n := len(f.label); n > labelW {
			labelW = n
		}
	}
	for _, f := range rows {
		label := f.label + strings.Repeat(" ", labelW-len(f.label))
		if color {
			label = colorize("2", label)
		}
		fmt.Fprintf(b, "  %s  %s\n", label, f.value)
	}
	if hasLocation(p) {
		note := ipLocationNote
		if color {
			note = colorize("2", note)
		}
		fmt.Fprintf(b, "\n  %s\n", note)
	}
}

func writeIPTable(b *strings.Builder, rows []ipField, p *infra.Profile) {
	b.WriteString("## IP address\n\n| Field | Value |\n| --- | --- |\n")
	for _, f := range rows {
		fmt.Fprintf(b, "| %s | %s |\n", mdCell(f.label), mdCell(f.value))
	}
	b.WriteString("\n")
	if hasLocation(p) {
		b.WriteString(ipLocationNote + "\n\n")
	}
}
