package casefile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/idrewlong/footprint/pkg/report"
)

// TestMain keeps every save in this package away from the operator's real
// signing key by pointing FOOTPRINT_SIGN_KEY at a throwaway directory.
func TestMain(m *testing.M) {
	keyDir, err := os.MkdirTemp("", "footprint-key-")
	if err != nil {
		panic(err)
	}
	os.Setenv(signKeyEnv, filepath.Join(keyDir, signKeyName))
	code := m.Run()
	os.RemoveAll(keyDir)
	os.Exit(code)
}

// useKey points saves at a fresh signing key for one test and returns its
// public half.
func useKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	path := filepath.Join(t.TempDir(), signKeyName)
	t.Setenv(signKeyEnv, path)
	priv, created, err := LoadOrCreateSigningKey(path)
	if err != nil || !created {
		t.Fatalf("create key: created=%v err=%v", created, err)
	}
	return priv.Public().(ed25519.PublicKey)
}

func saveCase(t *testing.T, dir, subject string, day int) {
	t.Helper()
	if _, err := Save(dir, Saved{
		Version:   "test",
		RanAt:     time.Date(2026, 1, day, 0, 0, 0, 0, time.UTC),
		Kind:      "identity",
		CaseID:    "C-1",
		Authority: "warrant",
		Operator:  "agent",
		Report:    report.Document{Email: subject},
	}); err != nil {
		t.Fatalf("save %s: %v", subject, err)
	}
}

func trusted(pub ed25519.PublicKey) VerifyOptions {
	return VerifyOptions{Trusted: []ed25519.PublicKey{pub}}
}

func TestLedgerChainAndVerify(t *testing.T) {
	pub := useKey(t)
	dir := t.TempDir()
	saveCase(t, dir, "a@example.com", 1)
	saveCase(t, dir, "b@example.com", 2)

	rep, err := Verify(dir, trusted(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Entries != 2 {
		t.Fatalf("clean ledger did not verify: %+v", rep)
	}
	entries, err := ReadLedger(dir)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Prev != "" || entries[1].Prev != entries[0].Hash {
		t.Fatal("entries do not chain")
	}
	if rep.Head != entries[1].Hash {
		t.Fatalf("head = %s, want the last entry's hash", rep.Head)
	}

	// Altering a signed field breaks the entry hash and the signature.
	path := filepath.Join(dir, ledgerName)
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.Replace(data, []byte("warrant"), []byte("forged!"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, _ := Verify(dir, trusted(pub)); rep.OK() {
		t.Fatal("verify passed after the ledger was altered")
	}
}

func TestSigningKeyStaysOutOfCaseDir(t *testing.T) {
	useKey(t)
	dir := t.TempDir()
	saveCase(t, dir, "a@example.com", 1)
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		if strings.Contains(f.Name(), "ed25519") || strings.HasSuffix(f.Name(), ".key") {
			t.Fatalf("case directory holds key material: %s", f.Name())
		}
	}
}

func TestSaveRefusesKeyInsideCaseDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(signKeyEnv, filepath.Join(dir, "keys", signKeyName))
	_, err := Save(dir, Saved{Kind: "identity", RanAt: time.Now(), Report: report.Document{Email: "a@example.com"}})
	if err == nil || !strings.Contains(err.Error(), "inside the case directory") {
		t.Fatalf("save with an in-directory key: err = %v", err)
	}
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") {
			t.Fatalf("a refused save left %s behind", f.Name())
		}
	}
}

// An attacker who can edit the case directory, but does not hold the
// signing key, rewrites a case and rebuilds the whole chain under a key of
// their own. Every hash, link, and signature is internally consistent, so
// only a verifier-chosen key can catch it.
func TestVerifyRejectsChainResignedWithAnotherKey(t *testing.T) {
	pub := useKey(t)
	dir := t.TempDir()
	saveCase(t, dir, "a@example.com", 1)
	saveCase(t, dir, "b@example.com", 2)

	entries, err := ReadLedger(dir)
	if err != nil {
		t.Fatal(err)
	}
	evilPub, evilPriv, _ := ed25519.GenerateKey(rand.Reader)
	var out bytes.Buffer
	prev := genesisPrev
	for i, e := range entries {
		if i == 0 {
			e.Authority = "none"
		}
		e.Prev = prev
		e.PubKey = base64.StdEncoding.EncodeToString(evilPub)
		e.Hash = e.entryHash()
		e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(evilPriv, []byte(e.Hash)))
		line, _ := json.Marshal(e)
		out.Write(append(line, '\n'))
		prev = e.Hash
	}
	if err := os.WriteFile(filepath.Join(dir, ledgerName), out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// Under the attacker's own key the forgery is self-consistent...
	if rep, _ := Verify(dir, trusted(evilPub)); !rep.OK() {
		t.Fatalf("test forgery is not self-consistent: %v", rep.Problems)
	}
	// ...and under the operator's trusted key it fails on every entry.
	rep, err := Verify(dir, trusted(pub))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Problems) != 2 || !strings.Contains(rep.Problems[0], "not signed by a trusted key") {
		t.Fatalf("problems = %v", rep.Problems)
	}
}

func TestVerifyRequiresTrustedKey(t *testing.T) {
	useKey(t)
	dir := t.TempDir()
	saveCase(t, dir, "a@example.com", 1)
	if _, err := Verify(dir, VerifyOptions{}); !errors.Is(err, ErrNoTrustedKey) {
		t.Fatalf("err = %v, want ErrNoTrustedKey", err)
	}
}

func TestVerifyHeadDetectsTruncation(t *testing.T) {
	pub := useKey(t)
	dir := t.TempDir()
	saveCase(t, dir, "a@example.com", 1)
	first, _ := Head(dir)
	saveCase(t, dir, "b@example.com", 2)
	head, _ := Head(dir)

	// An older head still verifies; the report counts what came after it.
	rep, err := Verify(dir, VerifyOptions{Trusted: []ed25519.PublicKey{pub}, Head: first[:minHeadPrefix]})
	if err != nil || !rep.OK() || rep.SinceHead != 1 {
		t.Fatalf("older head: rep=%+v err=%v", rep, err)
	}

	// Cut the last entry. The remaining prefix is a valid chain on its own.
	path := filepath.Join(dir, ledgerName)
	data, _ := os.ReadFile(path)
	lines := bytes.SplitAfter(bytes.TrimSpace(data), []byte("\n"))
	if err := os.WriteFile(path, lines[0], 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, _ := Verify(dir, trusted(pub)); !rep.OK() {
		t.Fatalf("truncated prefix should verify without a head: %v", rep.Problems)
	}
	rep, err = Verify(dir, VerifyOptions{Trusted: []ed25519.PublicKey{pub}, Head: head})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || !strings.Contains(strings.Join(rep.Problems, "\n"), "not in the ledger") {
		t.Fatalf("truncation not caught: %+v", rep)
	}

	if _, err := Verify(dir, VerifyOptions{Trusted: []ed25519.PublicKey{pub}, Head: "abc"}); err == nil {
		t.Fatal("a 3-character head was accepted")
	}
}

func TestLoadOrCreateSigningKeyReusesKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k", signKeyName)
	a, created, err := LoadOrCreateSigningKey(path)
	if err != nil || !created {
		t.Fatalf("first: created=%v err=%v", created, err)
	}
	b, created, err := LoadOrCreateSigningKey(path)
	if err != nil || created || !a.Equal(b) {
		t.Fatalf("second: created=%v err=%v same=%v", created, err, a.Equal(b))
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v err=%v", info.Mode().Perm(), err)
	}
	pub, err := ReadPublicKey(PublicKeyPath(path))
	if err != nil || !pub.Equal(a.Public()) {
		t.Fatalf("public key file: err=%v", err)
	}
}
