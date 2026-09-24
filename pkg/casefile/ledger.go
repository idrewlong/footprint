package casefile

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
// entry is signed with a local Ed25519 key, so an entry cannot be forged
// without the key. This is what lets an operator show a case file, and the
// order of a case's steps, have not been altered after the fact.
const (
	ledgerName  = "audit.log"
	keyName     = "footprint-ed25519.key"
	pubName     = "footprint-ed25519.pub"
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

// signingKey loads the ledger's Ed25519 private key, creating one on first
// use. The key never leaves the case directory and is written 0600.
func signingKey(dir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, keyName)
	data, err := os.ReadFile(path)
	if err == nil {
		raw, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if decErr != nil {
			return nil, fmt.Errorf("casefile: decode signing key: %w", decErr)
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("casefile: signing key has the wrong size")
		}
		return ed25519.PrivateKey(raw), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("casefile: read signing key: %w", err)
	}
	pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		return nil, fmt.Errorf("casefile: generate signing key: %w", genErr)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("casefile: create dir: %w", err)
	}
	encPriv := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(path, []byte(encPriv+"\n"), keyPerm); err != nil {
		return nil, fmt.Errorf("casefile: write signing key: %w", err)
	}
	encPub := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(filepath.Join(dir, pubName), []byte(encPub+"\n"), pubPerm); err != nil {
		return nil, fmt.Errorf("casefile: write public key: %w", err)
	}
	return priv, nil
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
	priv, err := signingKey(dir)
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

// VerifyReport is the outcome of checking a case directory's audit ledger.
type VerifyReport struct {
	Entries  int
	Problems []string
}

// OK reports whether the ledger verified with no problems.
func (v VerifyReport) OK() bool { return len(v.Problems) == 0 }

// Verify re-checks the audit ledger of a case directory. It confirms that
// every entry's signature is valid, that each entry links to the previous
// one, and that each referenced case file is present and unchanged. It names
// every problem it finds rather than stopping at the first.
func Verify(dir string) (VerifyReport, error) {
	entries, err := ReadLedger(dir)
	if err != nil {
		return VerifyReport{}, err
	}
	report := VerifyReport{Entries: len(entries)}
	prev := genesisPrev
	for i, entry := range entries {
		label := fmt.Sprintf("entry %d (%s)", i+1, entry.File)

		if entry.Prev != prev {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: broken chain: prev is %s, expected %s", label, short(entry.Prev), short(prev)))
		}
		if got := entry.entryHash(); got != entry.Hash {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: entry hash does not match its contents", label))
		}
		if !validSignature(entry) {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: signature is not valid", label))
		}
		if fileHash, ferr := sha256File(filepath.Join(dir, entry.File)); ferr != nil {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: case file missing or unreadable", label))
		} else if fileHash != entry.FileSHA256 {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: case file has been modified since it was saved", label))
		}
		prev = entry.Hash
	}
	return report, nil
}

func validSignature(entry Entry) bool {
	pub, err := base64.StdEncoding.DecodeString(entry.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(entry.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(entry.Hash), sig)
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
