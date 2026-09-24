package casefile

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The audit ledger is an append-only, tamper-evident record of every saved
// case. Each entry names the case, the operator, the legal authority, and a
// SHA-256 of the saved file. Entries are chained: an entry commits to the
// previous entry's hash, so a removed or altered entry breaks the chain. Each
// entry is signed with an Ed25519 key kept outside the case directory (see
// signkey.go), and Verify accepts only signatures from keys the operator
// names as trusted, so the chain cannot be rebuilt under a fresh key. The
// chain alone cannot show that entries were cut from the end, so Verify can
// also check a head hash the operator recorded elsewhere. Together these let
// an operator show a case file, and the order of a case's steps, have not
// been altered after the fact.
const (
	ledgerName  = "audit.log"
	ledgerPerm  = 0o600
	keyPerm     = 0o600
	pubPerm     = 0o644
	genesisPrev = ""
)

// Entry is one line of the audit ledger. Hash and Signature are computed over
// the other fields, so they are excluded when the entry hash is formed.
type Entry struct {
	Time       time.Time `json:"time"`
	Operator   string    `json:"operator,omitempty"`
	CaseID     string    `json:"case_id"`
	Authority  string    `json:"authority"`
	Kind       string    `json:"kind"`
	Subject    string    `json:"subject"`
	Version    string    `json:"version"`
	File       string    `json:"file"`
	FileSHA256 string    `json:"file_sha256"`
	Prev       string    `json:"prev"`
	Hash       string    `json:"hash"`
	Signature  string    `json:"signature"`
	PubKey     string    `json:"pubkey"`
}

// entryHash is the SHA-256 over the signed fields, in a fixed order. Hash and
// Signature are not part of it. It commits to Prev, so the entries form a
// chain, and to PubKey, so the signing key cannot be swapped silently.
func (e Entry) entryHash() string {
	var b strings.Builder
	b.WriteString(e.Time.UTC().Format(time.RFC3339Nano))
	b.WriteByte('\n')
	for _, field := range []string{
		e.Operator, e.CaseID, e.Authority, e.Kind, e.Subject,
		e.Version, e.File, e.FileSHA256, e.Prev, e.PubKey,
	} {
		b.WriteString(field)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// lastEntryHash returns the hash of the final ledger entry, or "" when the
// ledger does not exist yet. It does not verify the chain.
func lastEntryHash(dir string) (string, error) {
	entries, err := ReadLedger(dir)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return genesisPrev, nil
	}
	return entries[len(entries)-1].Hash, nil
}

// sha256File returns the hex SHA-256 of a file's bytes.
func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// appendLedger signs and appends one entry for a saved case. dir is the case
// directory, path is the saved file just written. It returns the new entry.
func appendLedger(dir, path string, saved Saved) (Entry, error) {
	fileHash, err := sha256File(path)
	if err != nil {
		return Entry{}, fmt.Errorf("casefile: hash case file: %w", err)
	}
	keyPath, err := SigningKeyPath()
	if err != nil {
		return Entry{}, err
	}
	if inside, err := keyInsideDir(keyPath, dir); err != nil {
		return Entry{}, fmt.Errorf("casefile: locate signing key: %w", err)
	} else if inside {
		return Entry{}, fmt.Errorf("casefile: signing key %s is inside the case directory; keep it elsewhere so the ledger cannot be re-signed by whoever can edit it", keyPath)
	}
	priv, _, err := LoadOrCreateSigningKey(keyPath)
	if err != nil {
		return Entry{}, err
	}
	prev, err := lastEntryHash(dir)
	if err != nil {
		return Entry{}, err
	}
	entry := Entry{
		Time:       saved.RanAt.UTC(),
		Operator:   saved.Operator,
		CaseID:     saved.CaseID,
		Authority:  saved.Authority,
		Kind:       saved.Kind,
		Subject:    Subject(saved.Report),
		Version:    saved.Version,
		File:       filepath.Base(path),
		FileSHA256: fileHash,
		Prev:       prev,
		PubKey:     base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
	}
	entry.Hash = entry.entryHash()
	sig := ed25519.Sign(priv, []byte(entry.Hash))
	entry.Signature = base64.StdEncoding.EncodeToString(sig)

	line, err := json.Marshal(entry)
	if err != nil {
		return Entry{}, fmt.Errorf("casefile: encode ledger entry: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, ledgerName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, ledgerPerm)
	if err != nil {
		return Entry{}, fmt.Errorf("casefile: open ledger: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Entry{}, fmt.Errorf("casefile: append ledger: %w", err)
	}
	return entry, nil
}

// ReadLedger reads every entry in the case directory's audit log, in order.
// A missing ledger is not an error; it returns no entries.
func ReadLedger(dir string) ([]Entry, error) {
	f, err := os.Open(filepath.Join(dir, ledgerName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("casefile: open ledger: %w", err)
	}
	defer f.Close()
	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("casefile: decode ledger entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("casefile: read ledger: %w", err)
	}
	return entries, nil
}

// VerifyOptions names what the ledger is checked against. Trusted must hold
// at least one key: a signature is only evidence when the verifier chooses
// the key, not the entry being verified. Head, when set, is a ledger hash
// (or a prefix of at least 12 hex characters) recorded outside the case
// directory; it must still be in the ledger, which catches cut-off entries.
type VerifyOptions struct {
	Trusted []ed25519.PublicKey
	Head    string
}

// VerifyReport is the outcome of checking a case directory's audit ledger.
type VerifyReport struct {
	Entries int
	// Head is the hash of the last entry, to record somewhere independent.
	Head string
	// SinceHead counts entries appended after the checked Head.
	SinceHead int
	Problems  []string
}

// OK reports whether the ledger verified with no problems.
func (v VerifyReport) OK() bool { return len(v.Problems) == 0 }

// ErrNoTrustedKey is returned when Verify is given no key to trust.
var ErrNoTrustedKey = errors.New("casefile: no trusted public key to verify signatures against")

const minHeadPrefix = 12

// Verify re-checks the audit ledger of a case directory. It confirms that
// every entry is signed by a trusted key, that each entry links to the
// previous one, that each referenced case file is present and unchanged,
// and, when opts.Head is set, that the recorded head is still in the ledger.
// It names every problem it finds rather than stopping at the first.
func Verify(dir string, opts VerifyOptions) (VerifyReport, error) {
	if len(opts.Trusted) == 0 {
		return VerifyReport{}, ErrNoTrustedKey
	}
	head := strings.ToLower(strings.TrimSpace(opts.Head))
	if head != "" && len(head) < minHeadPrefix {
		return VerifyReport{}, fmt.Errorf("casefile: head %q is too short; give at least %d hex characters", opts.Head, minHeadPrefix)
	}
	entries, err := ReadLedger(dir)
	if err != nil {
		return VerifyReport{}, err
	}
	report := VerifyReport{Entries: len(entries)}
	prev := genesisPrev
	headAt := -1
	for i, entry := range entries {
		label := fmt.Sprintf("entry %d (%s)", i+1, entry.File)

		if entry.Prev != prev {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: broken chain: prev is %s, expected %s", label, short(entry.Prev), short(prev)))
		}
		if got := entry.entryHash(); got != entry.Hash {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: entry hash does not match its contents", label))
		}
		if !trustedSignature(entry, opts.Trusted) {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: not signed by a trusted key", label))
		}
		if fileHash, ferr := sha256File(filepath.Join(dir, entry.File)); ferr != nil {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: case file missing or unreadable", label))
		} else if fileHash != entry.FileSHA256 {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: case file has been modified since it was saved", label))
		}
		if head != "" && headAt < 0 && strings.HasPrefix(entry.Hash, head) {
			headAt = i
		}
		prev = entry.Hash
	}
	report.Head = prev
	if head != "" {
		if headAt < 0 {
			report.Problems = append(report.Problems, fmt.Sprintf("recorded head %s is not in the ledger: entries were removed or the ledger was rewritten", short(head)))
		} else {
			report.SinceHead = len(entries) - 1 - headAt
		}
	}
	return report, nil
}

// trustedSignature reports whether the entry verifies under one of the
// trusted keys. The key named in the entry is not believed on its own; it
// must equal a trusted key, and the signature is checked with that key.
func trustedSignature(entry Entry, trusted []ed25519.PublicKey) bool {
	named, err := base64.StdEncoding.DecodeString(entry.PubKey)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(entry.Signature)
	if err != nil {
		return false
	}
	for _, key := range trusted {
		if bytes.Equal(named, key) && ed25519.Verify(key, []byte(entry.Hash), sig) {
			return true
		}
	}
	return false
}

// Head returns the hash of the last ledger entry in dir, or "" when there
// is no ledger yet. It does not verify the chain.
func Head(dir string) (string, error) {
	return lastEntryHash(dir)
}

func short(hash string) string {
	if hash == "" {
		return "(genesis)"
	}
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
