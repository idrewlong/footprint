package casefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/report"
)

func TestSaveLoadPermissionsAndRoundTrip(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "cases")
	evidence := "Sign-in lookup said this email is already registered."
	saved := Saved{
		Version:   "test",
		RanAt:     time.Date(2026, 9, 23, 20, 0, 0, 0, time.UTC),
		ElapsedMS: 1200,
		Kind:      "identity",
		Report: report.Document{
			Email: "me@example.com",
			Results: []checker.Result{
				{
					Site:     "adobe",
					Method:   "login",
					Status:   checker.StatusFound,
					Evidence: evidence,
				},
			},
		},
	}

	path, err := Save(dir, saved)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %04o, want 0700", dirInfo.Mode().Perm())
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %04o, want 0600", fileInfo.Mode().Perm())
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Report.Email != "me@example.com" {
		t.Fatalf("email = %q, want me@example.com", loaded.Report.Email)
	}
	if len(loaded.Report.Results) == 0 {
		t.Fatal("expected at least one result")
	}
	if loaded.Report.Results[0].Evidence != evidence {
		t.Fatalf("evidence = %q, want %q", loaded.Report.Results[0].Evidence, evidence)
	}
}

func TestDiffBuckets(t *testing.T) {
	oldDoc := report.Document{
		Results: []checker.Result{
			{Site: "adobe", Method: "login", Status: checker.StatusFound, Evidence: "adobe still"},
			{Site: "github", Method: "register", Status: checker.StatusNotFound},
			{Site: "slack", Method: "register", Status: checker.StatusFound, Evidence: "slack was found"},
			{Site: "zoom", Method: "register", Status: checker.StatusFound, Evidence: "zoom was found"},
			{Site: "dropbox", Method: "register", Status: checker.StatusFound, Evidence: "dropbox was found"},
			{Site: "reddit", Method: "register", Status: checker.StatusRateLimited},
		},
	}
	newDoc := report.Document{
		Results: []checker.Result{
			{Site: "adobe", Method: "login", Status: checker.StatusFound, Evidence: "adobe still"},
			{Site: "github", Method: "register", Status: checker.StatusFound, Evidence: "github added"},
			{Site: "slack", Method: "register", Status: checker.StatusNotFound},
			{Site: "zoom", Method: "register", Status: checker.StatusRateLimited},
			{Site: "reddit", Method: "register", Status: checker.StatusFound, Evidence: "reddit recovered"},
		},
	}

	d := Diff(oldDoc, newDoc)

	assertSites(t, "Still", d.Still, "adobe")
	assertSites(t, "Added", d.Added, "github", "reddit")
	assertSites(t, "Gone", d.Gone, "slack")
	assertSites(t, "Unchecked", d.Unchecked, "zoom", "dropbox")
}

func TestLoadRejectsBareReportJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bare.json")
	doc := report.Document{
		Email: "me@example.com",
		Summary: report.Summary{
			Found: 1,
		},
		Results: []checker.Result{
			{Site: "adobe", Method: "login", Status: checker.StatusFound},
		},
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := report.WriteJSON(f, doc); err != nil {
		t.Fatal(err)
	}
	f.Close()

	loaded, err := Load(path)
	if err == nil {
		t.Fatalf("expected error, got %+v", loaded)
	}
	if !strings.Contains(err.Error(), "not a footprint case file") || !strings.Contains(err.Error(), "--save") {
		t.Fatalf("error = %v", err)
	}
	if loaded.Report.Email != "" || len(loaded.Report.Results) != 0 {
		t.Fatalf("must not return an empty report on success path: %+v", loaded)
	}
}

func TestMergeKeepsLaterDuplicateSite(t *testing.T) {
	a := report.Document{
		Email: "me@example.com",
		Results: []checker.Result{
			{Site: "adobe", Method: "login", Status: checker.StatusNotFound, Evidence: "earlier"},
		},
	}
	b := report.Document{
		Email: "me@example.com",
		Results: []checker.Result{
			{Site: "adobe", Method: "login", Status: checker.StatusFound, Evidence: "later hit"},
		},
	}
	merged, err := Merge(a, b)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(merged.Results) != 1 {
		t.Fatalf("results len = %d, want 1", len(merged.Results))
	}
	if merged.Results[0].Status != checker.StatusFound || merged.Results[0].Evidence != "later hit" {
		t.Fatalf("kept %+v", merged.Results[0])
	}
	if merged.Summary.Found != 1 || merged.Summary.NotFound != 0 {
		t.Fatalf("summary = %+v", merged.Summary)
	}
}

func TestMergeEmailAndDomain(t *testing.T) {
	emailDoc := report.Document{
		Email: "me@example.com",
		Summary: report.Summary{
			Found: 1,
		},
		Results: []checker.Result{
			{Site: "adobe", Method: "login", Status: checker.StatusFound},
		},
	}
	domainDoc := report.Document{
		SubjectDomain: "example.com",
		Summary: report.Summary{
			NotFound: 1,
		},
		Results: []checker.Result{
			{Site: "mx", Method: "dns", Status: checker.StatusNotFound},
		},
	}

	merged, err := Merge(emailDoc, domainDoc)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if merged.Email != "me@example.com" {
		t.Fatalf("email = %q", merged.Email)
	}
	if merged.SubjectDomain != "example.com" {
		t.Fatalf("subject_domain = %q", merged.SubjectDomain)
	}
	if len(merged.Results) != 2 {
		t.Fatalf("results len = %d, want 2", len(merged.Results))
	}
	want := report.Summarize(merged.Results)
	if merged.Summary != want {
		t.Fatalf("summary = %+v, want %+v from Summarize", merged.Summary, want)
	}
	if merged.Summary.Found != 1 || merged.Summary.NotFound != 1 {
		t.Fatalf("summary counts = %+v, want found=1 not_found=1", merged.Summary)
	}
}

func TestMergeConflictingEmails(t *testing.T) {
	a := report.Document{Email: "a@example.com"}
	b := report.Document{Email: "b@example.com"}
	if _, err := Merge(a, b); err == nil {
		t.Fatal("expected error for conflicting emails")
	}
}

func assertSites(t *testing.T, bucket string, rows []checker.Result, want ...string) {
	t.Helper()
	got := make([]string, len(rows))
	for i, r := range rows {
		got[i] = r.Site
	}
	if len(got) != len(want) {
		t.Fatalf("%s sites = %v, want %v", bucket, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s sites = %v, want %v", bucket, got, want)
		}
	}
}
