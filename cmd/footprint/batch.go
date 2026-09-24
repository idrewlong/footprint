package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/report"
)

// readSubjects reads one subject per line from a file. Blank lines and lines
// beginning with '#' are ignored, so a list can carry comments. Duplicate
// subjects are kept once, in first-seen order.
func readSubjects(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("batch: open %s: %w", path, err)
	}
	defer f.Close()
	var subjects []string
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		subjects = append(subjects, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("batch: read %s: %w", path, err)
	}
	return subjects, nil
}

// scanRunner runs one subject and returns its scored report. It matches the
// closure runScan builds, so a batch reuses the single-subject pipeline.
type scanRunner func(email, username string) (report.Document, []checker.Result, time.Time, time.Duration)

// runScanBatch scans every subject in a list. It validates each subject,
// skipping and naming invalid ones on stderr rather than treating them as a
// clean result. JSON output is one array of documents; human and Markdown
// output separate the per-subject reports. With --save, each subject is
// written and logged to the audit ledger separately.
func runScanBatch(ctx context.Context, stdout, stderr io.Writer, subjects []string, kind string, run scanRunner, asJSON, asMarkdown bool, saveReq saveRequest) int {
	human := !asJSON && !asMarkdown
	var docs []report.Document
	var starts []time.Time
	var elapseds []time.Duration
	skipped := 0
	code := 0

	for _, subject := range subjects {
		if ctx.Err() != nil {
			fmt.Fprintln(stderr, "footprint: batch cancelled")
			break
		}
		var email, username string
		switch kind {
		case "email":
			norm, ok := normalizeEmail(subject)
			if !ok {
				fmt.Fprintf(stderr, "footprint: skipping invalid email %q\n", subject)
				skipped++
				continue
			}
			email = norm
		case "username":
			norm, ok := normalizeUsername(subject)
			if !ok {
				fmt.Fprintf(stderr, "footprint: skipping invalid username %q\n", subject)
				skipped++
				continue
			}
			username = norm
		}
		full, _, start, elapsed := run(email, username)
		docs = append(docs, full)
		starts = append(starts, start)
		elapseds = append(elapseds, elapsed)

		if !asJSON {
			if human && len(docs) > 1 {
				fmt.Fprintln(stdout)
			}
			if err := writeReport(stdout, stderr, full, asJSON, asMarkdown, start, elapsed); err != nil {
				code = 1
			}
		}
		if c := maybeSave(stderr, saveReq, full, start, elapsed); c != 0 {
			code = c
		}
	}

	if asJSON {
		if err := writeBatchJSON(stdout, docs); err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(stderr, "batch: %s scanned, %d skipped\n", counted(len(docs), "subject", "subjects"), skipped)
	if len(docs) == 0 {
		return 2
	}
	return code
}

// writeBatchJSON writes the batch as a JSON array of report documents, in the
// same shape and indentation as a single --json report.
func writeBatchJSON(w io.Writer, docs []report.Document) error {
	if docs == nil {
		docs = []report.Document{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(docs); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}
