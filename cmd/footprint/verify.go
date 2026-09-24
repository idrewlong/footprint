package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/idrewlong/footprint/pkg/casefile"
)

// runVerify checks the tamper-evident audit ledger of a case directory. It
// confirms every saved case file is unchanged, that the ledger's chain is
// intact, that each entry is signed by a trusted key, and, with --head, that
// a head hash recorded elsewhere is still in the ledger. It exits non-zero
// when anything fails, so it can gate a workflow.
func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var caseDir, head string
	var pubKeys stringList
	fs.StringVar(&caseDir, "case-dir", "", "case directory to verify")
	fs.Var(&pubKeys, "pubkey", "trusted public key file (repeatable)")
	fs.StringVar(&head, "head", "", "ledger head hash recorded outside the case directory")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	flags, positionals, splitErr := splitArgs(args, map[string]bool{
		"h":    true,
		"help": true,
	}, map[string]bool{
		"case-dir": true,
		"pubkey":   true,
		"head":     true,
	})
	if splitErr != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", splitErr)
		return 2
	}
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	// The directory may be given positionally or with --case-dir.
	if len(positionals) == 1 && caseDir == "" {
		caseDir = positionals[0]
	} else if len(positionals) > 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	dir := caseDir
	if dir == "" {
		var err error
		dir, err = casefile.DefaultDir()
		if err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return 1
		}
	}
	trusted, code := trustedKeys(pubKeys, stderr)
	if code != 0 {
		return code
	}
	report, err := casefile.Verify(dir, casefile.VerifyOptions{Trusted: trusted, Head: head})
	if err != nil {
		fmt.Fprintf(stderr, "footprint: %v\n", err)
		return 1
	}
	if report.Entries == 0 && head == "" {
		fmt.Fprintf(stdout, "No audit ledger in %s.\n", dir)
		return 0
	}
	keys := make([]string, len(trusted))
	for i, k := range trusted {
		keys[i] = casefile.Fingerprint(k)
	}
	if report.OK() {
		fmt.Fprintf(stdout, "OK: %s verified, chain intact, signed by trusted key %s.\n", counted(report.Entries, "case", "cases"), strings.Join(keys, ", "))
		if head != "" {
			fmt.Fprintf(stdout, "Recorded head found; %s appended since.\n", counted(report.SinceHead, "entry", "entries"))
		}
		fmt.Fprintf(stdout, "head %s\n", report.Head)
		return 0
	}
	fmt.Fprintf(stdout, "FAILED: %d problem(s) in %s\n", len(report.Problems), dir)
	for _, p := range report.Problems {
		fmt.Fprintf(stdout, "- %s\n", p)
	}
	return 1
}

// trustedKeys loads the --pubkey files, or when none is given, the public
// key next to this machine's signing key. The key named inside the ledger is
// never used on its own: a ledger cannot vouch for itself.
func trustedKeys(paths []string, stderr io.Writer) ([]ed25519.PublicKey, int) {
	if len(paths) == 0 {
		keyPath, err := casefile.SigningKeyPath()
		if err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return nil, 1
		}
		pubPath := casefile.PublicKeyPath(keyPath)
		if _, err := os.Stat(pubPath); errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "footprint: no trusted public key: %s does not exist; pass --pubkey with the signer's public key file\n", pubPath)
			return nil, 1
		}
		paths = []string{pubPath}
	}
	keys := make([]ed25519.PublicKey, 0, len(paths))
	for _, path := range paths {
		key, err := casefile.ReadPublicKey(path)
		if err != nil {
			fmt.Fprintf(stderr, "footprint: %v\n", err)
			return nil, 1
		}
		keys = append(keys, key)
	}
	return keys, 0
}
