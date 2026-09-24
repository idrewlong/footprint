// Command footprint-mcp exposes footprint's checks to AI assistants over
// the Model Context Protocol on stdio. Checks run on this machine and go
// only to the sites being checked.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/idrewlong/footprint/internal/httpx"
	"github.com/idrewlong/footprint/pkg/casefile"
	"github.com/idrewlong/footprint/pkg/checker"
	"github.com/idrewlong/footprint/pkg/sites"
)

const usage = `footprint-mcp serves footprint's checks over MCP on stdio.

Usage:
  footprint-mcp [flags]

Launch flags set policy for every tool call; the assistant cannot change them.
  --allow-notify      allow checks that can email the address (password reset)
  --proxy url         route checks through http, https, socks5, or socks5h
  --concurrency n     parallel checks (default 16)
  --timeout 10s       per-site timeout
  --save              save every scan_email to the case directory
  --case-dir path     case directory (default ~/.local/share/footprint)
  --case-id id        case identifier recorded with saved scans (required with --save)
  --authority text    legal authority recorded with saved scans (required with --save)

Client setup:
  claude mcp add footprint -- footprint-mcp
`

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	cfg, code := parseConfig(args, stderr)
	if code != 0 {
		return code
	}
	if t, ok := cfg.transport.(interface{ CloseIdleConnections() }); ok {
		defer t.CloseIdleConnections()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// stdout carries the protocol; everything else goes to stderr.
	log.SetOutput(stderr)
	if err := newServer(cfg).Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		fmt.Fprintf(stderr, "footprint-mcp: %v\n", err)
		return 1
	}
	return 0
}

func parseConfig(args []string, stderr io.Writer) (config, int) {
	fs := flag.NewFlagSet("footprint-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	cfg := config{version: toolVersion(), catalog: sites.Select, operator: operator()}
	var proxyURL string
	fs.BoolVar(&cfg.allowNotify, "allow-notify", false, "allow checks that can email the address")
	fs.StringVar(&proxyURL, "proxy", "", "route checks through a proxy")
	fs.IntVar(&cfg.concurrency, "concurrency", checker.DefaultConcurrency, "parallel checks")
	fs.DurationVar(&cfg.timeout, "timeout", checker.DefaultTimeout, "per-site timeout")
	fs.BoolVar(&cfg.save, "save", false, "save every scan_email to the case directory")
	fs.StringVar(&cfg.caseDir, "case-dir", "", "case directory")
	fs.StringVar(&cfg.caseID, "case-id", "", "case identifier recorded with saved scans")
	fs.StringVar(&cfg.authority, "authority", "", "legal authority recorded with saved scans")
	if err := fs.Parse(args); err != nil {
		return config{}, 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return config{}, 2
	}
	if cfg.concurrency < 1 {
		fmt.Fprintln(stderr, "footprint-mcp: --concurrency must be at least 1")
		return config{}, 2
	}
	if cfg.timeout <= 0 {
		fmt.Fprintln(stderr, "footprint-mcp: --timeout must be greater than 0")
		return config{}, 2
	}
	cfg.caseID = strings.TrimSpace(cfg.caseID)
	cfg.authority = strings.TrimSpace(cfg.authority)
	if cfg.save {
		// A saved case is an investigative record, so it must name its case
		// and authority before the first scan, not after.
		if cfg.caseID == "" || cfg.authority == "" {
			fmt.Fprintln(stderr, "footprint-mcp: --save requires --case-id and --authority")
			return config{}, 2
		}
		if cfg.caseDir == "" {
			dir, err := casefile.DefaultDir()
			if err != nil {
				fmt.Fprintf(stderr, "footprint-mcp: %v\n", err)
				return config{}, 1
			}
			cfg.caseDir = dir
		}
	}
	// A bad proxy is fatal so traffic never falls back to the operator's IP.
	transport, err := httpx.NewTransportProxy(proxyURL)
	if err != nil {
		fmt.Fprintf(stderr, "footprint-mcp: %v\n", err)
		return config{}, 2
	}
	cfg.transport = transport
	return cfg, 0
}

func toolVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	return info.Main.Version
}
