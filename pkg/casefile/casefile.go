// Package casefile saves and compares local footprint reports.
package casefile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/report"
)

// Saved is one scan written under the case directory.
type Saved struct {
	Version   string          `json:"version"`
	RanAt     time.Time       `json:"ran_at"`
	ElapsedMS int64           `json:"elapsed_ms"`
	Kind      string          `json:"kind"`
	Report    report.Document `json:"report"`
}

// DefaultDir is ~/.local/share/footprint.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("casefile: home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share", "footprint"), nil
}

// Save writes saved as a new 0600 JSON file under dir (created 0700).
func Save(dir string, saved Saved) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("casefile: create dir: %w", err)
	}
	name := saved.RanAt.UTC().Format("20060102T150405.000000000Z") + "-" + saved.Kind + "-" + subjectSlug(saved.Report) + ".json"
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("casefile: create file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(saved); err != nil {
		return "", fmt.Errorf("casefile: encode: %w", err)
	}
	return path, nil
}

// Load reads a saved case file.
func Load(path string) (Saved, error) {
	f, err := os.Open(path)
	if err != nil {
		return Saved{}, fmt.Errorf("casefile: open: %w", err)
	}
	defer f.Close()
	var saved Saved
	if err := json.NewDecoder(f).Decode(&saved); err != nil {
		return Saved{}, fmt.Errorf("casefile: decode: %w", err)
	}
	return saved, nil
}

// Delta is the four-way comparison of two reports.
type Delta struct {
	Added     []checker.Result
	Gone      []checker.Result
	Unchecked []checker.Result
	Still     []checker.Result
}

func rowKey(r checker.Result) string {
	return r.Method + "\x00" + r.Site
}

// Diff classifies found rows between old and new. A blocked or missing
// re-check is Unchecked, never Gone.
func Diff(old, new report.Document) Delta {
	oldBy := map[string]checker.Result{}
	for _, r := range old.Results {
		oldBy[rowKey(r)] = r
	}
	newBy := map[string]checker.Result{}
	for _, r := range new.Results {
		newBy[rowKey(r)] = r
	}

	var d Delta
	seen := map[string]struct{}{}

	for _, nr := range new.Results {
		key := rowKey(nr)
		seen[key] = struct{}{}
		or, hadOld := oldBy[key]
		switch {
		case nr.Status == checker.StatusFound && (!hadOld || or.Status == checker.StatusNotFound):
			d.Added = append(d.Added, nr)
		case nr.Status == checker.StatusFound && hadOld && or.Status == checker.StatusFound:
			d.Still = append(d.Still, nr)
		case hadOld && or.Status == checker.StatusFound && nr.Status == checker.StatusNotFound:
			d.Gone = append(d.Gone, or)
		case hadOld && or.Status == checker.StatusFound && nr.Status != checker.StatusFound:
			d.Unchecked = append(d.Unchecked, nr)
		}
	}

	for _, or := range old.Results {
		key := rowKey(or)
		if _, ok := seen[key]; ok {
			continue
		}
		if or.Status == checker.StatusFound {
			d.Unchecked = append(d.Unchecked, or)
		}
	}
	return d
}

// WriteDiff prints Added, Gone, Unchecked, then Still (count only).
func WriteDiff(w io.Writer, d Delta) error {
	sections := []struct {
		title string
		rows  []checker.Result
		count bool
	}{
		{"Added", d.Added, false},
		{"Gone", d.Gone, false},
		{"Unchecked", d.Unchecked, false},
		{"Still", d.Still, true},
	}
	for i, sec := range sections {
		if i > 0 {
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s\n", sec.title); err != nil {
			return err
		}
		if sec.count {
			if _, err := fmt.Fprintf(w, "%d\n", len(sec.rows)); err != nil {
				return err
			}
			continue
		}
		for _, r := range sec.rows {
			text := r.Evidence
			if text == "" {
				text = string(r.Status)
			}
			if _, err := fmt.Fprintf(w, "- %s (%s): %s\n", r.Site, r.Method, text); err != nil {
				return err
			}
		}
	}
	return nil
}

// Merge combines documents. Conflicting non-empty subject fields fail.
// Summary is recomputed from the concatenated rows.
func Merge(docs ...report.Document) (report.Document, error) {
	var out report.Document
	for _, doc := range docs {
		if err := mergeSubject(&out.Email, doc.Email, "email"); err != nil {
			return report.Document{}, err
		}
		if err := mergeSubject(&out.Username, doc.Username, "username"); err != nil {
			return report.Document{}, err
		}
		if err := mergeSubject(&out.SubjectDomain, doc.SubjectDomain, "subject_domain"); err != nil {
			return report.Document{}, err
		}
		if err := mergeSubject(&out.SubjectIP, doc.SubjectIP, "subject_ip"); err != nil {
			return report.Document{}, err
		}
		if err := mergeSubject(&out.SubjectEntity, doc.SubjectEntity, "subject_entity"); err != nil {
			return report.Document{}, err
		}
		out.Results = append(out.Results, doc.Results...)
	}
	out.Summary = report.Summarize(out.Results)
	return out, nil
}

func mergeSubject(dst *string, src, name string) error {
	if src == "" {
		return nil
	}
	if *dst != "" && *dst != src {
		return fmt.Errorf("casefile: conflicting %s: %q and %q", name, *dst, src)
	}
	*dst = src
	return nil
}

func subjectSlug(doc report.Document) string {
	raw := ""
	switch {
	case doc.Email != "":
		raw = doc.Email
	case doc.Username != "":
		raw = doc.Username
	case doc.SubjectDomain != "":
		raw = doc.SubjectDomain
	case doc.SubjectIP != "":
		raw = doc.SubjectIP
	case doc.SubjectEntity != "":
		raw = doc.SubjectEntity
	}
	raw = strings.ToLower(raw)
	var b strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	return b.String()
}
