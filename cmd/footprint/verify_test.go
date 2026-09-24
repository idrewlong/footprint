package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/idrewlong/footprint/pkg/checker"
)

// TestMain keeps every --save in this package away from the operator's real
// signing key.
func TestMain(m *testing.M) {
	keyDir, err := os.MkdirTemp("", "footprint-key-")
	if err != nil {
		panic(err)
	}
	os.Setenv("FOOTPRINT_SIGN_KEY", filepath.Join(keyDir, "audit-ed25519.key"))
	code := m.Run()
	os.RemoveAll(keyDir)
	os.Exit(code)
}

func saveOneCase(t *testing.T, dir string) string {
	t.Helper()
	catalog := func(categories, names []string) ([]checker.Site, error) {
		return []checker.Site{
			fakeSite{name: "alpha", domain: "alpha.example", category: "dev", method: "register", status: checker.StatusFound},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := executeCatalog([]string{"scan", "email", "me@example.com", "--save", "--case-dir", dir, "--case-id", "CASE-9", "--authority", "warrant"}, &stdout, &stderr, catalog); code != 0 {
		t.Fatalf("save failed: %s", stderr.String())
	}
	for _, line := range strings.Split(stderr.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, "audit head "); ok {
			return strings.Fields(rest)[0]
		}
	}
	t.Fatalf("save did not print the audit head:\n%s", stderr.String())
	return ""
}

func TestKeygenThenVerify(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "keys", "audit-ed25519.key")
	t.Setenv("FOOTPRINT_SIGN_KEY", keyPath)

	var out, errb bytes.Buffer
	if code := execute([]string{"keygen"}, &out, &errb); code != 0 {
		t.Fatalf("keygen: %s", errb.String())
	}
	if !strings.Contains(out.String(), "Created signing key") || !strings.Contains(out.String(), "Fingerprint") {
		t.Fatalf("keygen output:\n%s", out.String())
	}
	before, _ := os.ReadFile(keyPath)
	out.Reset()
	if code := execute([]string{"keygen"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "already exists") {
		t.Fatalf("second keygen: code %d\n%s", code, out.String())
	}
	if after, _ := os.ReadFile(keyPath); !bytes.Equal(before, after) {
		t.Fatal("keygen overwrote an existing key")
	}

	dir := t.TempDir()
	head := saveOneCase(t, dir)
	out.Reset()
	if code := execute([]string{"verify", dir, "--head", head}, &out, &errb); code != 0 {
		t.Fatalf("verify failed:\n%s%s", out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "head "+head) {
		t.Fatalf("verify did not print the head:\n%s", out.String())
	}
}

func TestVerifyWithWrongPubkeyFails(t *testing.T) {
	t.Setenv("FOOTPRINT_SIGN_KEY", filepath.Join(t.TempDir(), "audit-ed25519.key"))
	dir := t.TempDir()
	saveOneCase(t, dir)

	// A different operator's key is not trusted for this ledger.
	other := filepath.Join(t.TempDir(), "other.key")
	t.Setenv("FOOTPRINT_SIGN_KEY", other)
	var out, errb bytes.Buffer
	if code := execute([]string{"keygen"}, &out, &errb); code != 0 {
		t.Fatal(errb.String())
	}
	out.Reset()
	if code := execute([]string{"verify", dir, "--pubkey", other + ".pub"}, &out, &errb); code == 0 {
		t.Fatalf("verify passed under an untrusted key:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "not signed by a trusted key") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestVerifyWithoutTrustedKeyFails(t *testing.T) {
	t.Setenv("FOOTPRINT_SIGN_KEY", filepath.Join(t.TempDir(), "never-created.key"))
	var out, errb bytes.Buffer
	if code := execute([]string{"verify", t.TempDir()}, &out, &errb); code == 0 {
		t.Fatalf("verify passed with no trusted key:\n%s", out.String())
	}
	if !strings.Contains(errb.String(), "--pubkey") {
		t.Fatalf("error did not point to --pubkey:\n%s", errb.String())
	}
}
