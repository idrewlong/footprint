package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/idrewlong/footprint/pkg/casefile"
)

// runKeygen creates the audit signing key, or reports the one already in
// place. The key lives outside every case directory (FOOTPRINT_SIGN_KEY or
// the user config directory) so the ledger cannot be re-signed by whoever
// can edit it. An existing key is never overwritten.
func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	keyPath, err := casefile.SigningKeyPath()
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	priv, created, err := casefile.LoadOrCreateSigningKey(keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	if created {
		fmt.Fprintf(stdout, "Created signing key %s\n", keyPath)
	} else {
		fmt.Fprintf(stdout, "Signing key already exists at %s (not changed)\n", keyPath)
	}
	pubPath, _ := filepath.Abs(casefile.PublicKeyPath(keyPath))
	fmt.Fprintf(stdout, "Public key  %s\n", pubPath)
	fmt.Fprintf(stdout, "Fingerprint %s\n", casefile.Fingerprint(priv.Public().(ed25519.PublicKey)))
	fmt.Fprintln(stdout, "Give the public key to whoever verifies your case files: footprint verify --pubkey <file>")
	return 0
}
