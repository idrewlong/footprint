package casefile

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The audit signing key lives outside every case directory. A key kept next
// to the ledger it signs proves nothing: whoever can rewrite the ledger can
// read the key and re-sign it. The default is the user's config directory;
// FOOTPRINT_SIGN_KEY points somewhere else, such as removable media.
const (
	signKeyEnv   = "FOOTPRINT_SIGN_KEY"
	signKeyName  = "audit-ed25519.key"
	pubKeySuffix = ".pub"
)

// SigningKeyPath returns where the audit signing key is kept: the
// FOOTPRINT_SIGN_KEY path when set, else the user config directory.
func SigningKeyPath() (string, error) {
	if path := strings.TrimSpace(os.Getenv(signKeyEnv)); path != "" {
		return filepath.Abs(path)
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("casefile: config directory: %w", err)
	}
	return filepath.Join(cfg, "footprint", signKeyName), nil
}

// PublicKeyPath is the public half's file, next to the private key.
func PublicKeyPath(keyPath string) string {
	return keyPath + pubKeySuffix
}

// LoadOrCreateSigningKey reads the Ed25519 private key at path, creating it
// (0600, in a 0700 directory) with its public key beside it on first use.
// created reports whether a new key was made.
func LoadOrCreateSigningKey(path string) (priv ed25519.PrivateKey, created bool, err error) {
	priv, err = readSigningKey(path)
	if err == nil {
		return priv, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("casefile: generate signing key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("casefile: create key dir: %w", err)
	}
	// O_EXCL so two saves racing on first use cannot each write a key.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, keyPerm)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			priv, err = readSigningKey(path)
			return priv, false, err
		}
		return nil, false, fmt.Errorf("casefile: write signing key: %w", err)
	}
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(path)
		return nil, false, fmt.Errorf("casefile: write signing key: %w", werr)
	}
	if err := os.WriteFile(PublicKeyPath(path), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), pubPerm); err != nil {
		return nil, false, fmt.Errorf("casefile: write public key: %w", err)
	}
	return priv, true, nil
}

func readSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("casefile: read signing key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("casefile: decode signing key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("casefile: signing key has the wrong size")
	}
	return ed25519.PrivateKey(raw), nil
}

// ReadPublicKey reads a base64 Ed25519 public key file, as written next to
// the signing key.
func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("casefile: read public key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("casefile: %s is not an Ed25519 public key", path)
	}
	return ed25519.PublicKey(raw), nil
}

// Fingerprint is a short, stable name for a public key: the first 16 hex
// characters of its SHA-256, grouped for reading aloud or writing down.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	h := hex.EncodeToString(sum[:8])
	return h[0:4] + ":" + h[4:8] + ":" + h[8:12] + ":" + h[12:16]
}

// keyInsideDir reports whether keyPath is dir itself or lies under it.
func keyInsideDir(keyPath, dir string) (bool, error) {
	absKey, err := filepath.Abs(keyPath)
	if err != nil {
		return false, err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(resolveExisting(absDir), resolveExisting(absKey))
	if err != nil {
		return false, nil
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

// resolveExisting resolves symlinks in the longest part of path that exists
// and keeps the rest as written, so /tmp and /private/tmp compare equal even
// for a key whose directory has not been created yet.
func resolveExisting(path string) string {
	rest := ""
	for p := path; ; p = filepath.Dir(p) {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(r, rest)
		}
		if filepath.Dir(p) == p {
			return path
		}
		rest = filepath.Join(filepath.Base(p), rest)
	}
}
