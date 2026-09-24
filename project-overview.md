# footprint

> Find every account tied to an email address.

`footprint` is an open-source OSINT tool written in Go. It checks which online services have an account registered to any email address, using the same public signup, login, and password-reset signals that tools like [Holehe](https://github.com/megadose/holehe) pioneered. It ships as a single binary with three front ends over one shared core:

- **CLI**: scriptable, JSON output
- **TUI**: live, interactive results table (Bubble Tea)
- **MCP server**: lets AI assistants like Claude run lookups and work with the results

*(`footprint` is a working name.)*

---

## Goals

- Fast, concurrent checks across 100+ sites from a single static binary
- Honest results: clearly distinguish *found*, *not found*, *rate limited*, and *error*
- Actionable output: link each found account to its deletion or security settings page
- Easy to extend: adding a site is one self-contained file with a test
- Local-first: checks run from the user's machine and IP, and no data leaves it

## Non-goals

- A hosted public lookup service
- Credential checking, password dumps, or anything that attempts to log in

---

## Architecture

```
footprint/
├── cmd/
│   ├── footprint/        # CLI + TUI entrypoint
│   └── footprint-mcp/    # MCP server entrypoint
├── pkg/
│   ├── checker/          # engine: concurrency, timeouts, results
│   ├── sites/            # one file per site check
│   └── report/           # JSON, table, and markdown renderers
├── internal/
│   └── httpx/            # shared client, UA rotation, cookie jar helpers
├── testdata/             # recorded HTTP fixtures per site
├── .goreleaser.yaml
└── README.md
```

The CLI, TUI, and MCP server contain no site logic. They call `pkg/checker` and render the results.

### Core types

```go
package checker

type Status string

const (
    StatusFound       Status = "found"
    StatusNotFound    Status = "not_found"
    StatusRateLimited Status = "rate_limited"
    StatusError       Status = "error"
)

type Result struct {
    Site        string        `json:"site"`
    Domain      string        `json:"domain"`
    Category    string        `json:"category"`   // social, shopping, dev, etc.
    Method      string        `json:"method"`     // register | login | password_reset
    Status      Status        `json:"status"`
    DeleteURL   string        `json:"delete_url,omitempty"`
    SecurityURL string        `json:"security_url,omitempty"`
    Detail      string        `json:"detail,omitempty"`
    Duration    time.Duration `json:"duration_ms"`
}

type Site interface {
    Name() string
    Domain() string
    Category() string
    Method() string
    Check(ctx context.Context, c *http.Client, email string) Result
}
```

### Engine

- Every registered `Site` is run in a goroutine, with concurrency capped by a semaphore (default 16, `--concurrency` flag).
- Each check gets its own context timeout (default 10s), so one slow site never stalls the run.
- Results stream over a channel. The TUI renders them as they arrive, and the CLI and MCP server collect them.
- A per-domain backoff marks a site `rate_limited` on 429s or known block pages instead of reporting a false `not_found`.

```go
func Run(ctx context.Context, email string, sites []Site, opts Options) <-chan Result
```

### Site checks

Each site lives in its own file under `pkg/sites/` and registers itself:

```go
package sites

func init() { Register(&github{}) }

type github struct{}

func (github) Name() string     { return "github" }
func (github) Domain() string   { return "github.com" }
func (github) Category() string { return "dev" }
func (github) Method() string   { return "register" }

func (g github) Check(ctx context.Context, c *http.Client, email string) checker.Result {
    // 1. fetch signup page, extract CSRF token (goquery)
    // 2. POST email to the availability endpoint
    // 3. map the response to found / not_found / rate_limited / error
}
```

Every site ships with recorded fixtures in `testdata/<site>/` covering found, not-found, and rate-limited responses, so CI can test parsing without hitting live sites. A separate, manually triggered `live` test job hits real endpoints and reports which checks have broken.

---

## CLI

```bash
footprint scan email me@example.com                 # email accounts only
footprint scan username octocat                     # public profiles only
footprint scan email me@example.com username octocat
footprint scan email me@example.com --json          # every status, machine-readable
footprint scan email me@example.com --md > audit.md # every status, with delete links
footprint sites                                     # list supported sites
footprint sites --category shopping
```

## TUI

`footprint` with no arguments opens the interactive view:

- Email input, then a live table filling in as checks finish
- Status icons, filterable by status or category
- `enter` on a found account opens its delete or security page in the browser
- `r` retries rate-limited or errored checks
- `e` exports the report as markdown or JSON

Built with Bubble Tea, Bubbles (table, spinner, text input), and Lip Gloss.

---

## MCP server

`footprint-mcp` exposes the engine to AI assistants over the Model Context Protocol, built on the official Go SDK (`github.com/modelcontextprotocol/go-sdk`).

### Transport

- **stdio** (default): runs locally, launched by the client. Checks go out from the user's own IP.
- **Streamable HTTP** (optional, `--http :8080`): for local networks only. It binds to localhost unless explicitly overridden.

### Tools

| Tool | Input | Returns |
|---|---|---|
| `scan_email` | `email`, `categories?`, `only_found?` | Summary counts plus a list of `Result` |
| `check_site` | `email`, `site` | A single `Result`, useful for retrying rate-limited sites |
| `list_sites` | `category?` | Supported sites and methods |

Example `scan_email` response:

```json
{
  "email": "me@example.com",
  "summary": { "found": 8, "not_found": 104, "rate_limited": 3, "error": 1 },
  "results": [
    {
      "site": "adobe",
      "domain": "adobe.com",
      "status": "found",
      "delete_url": "https://account.adobe.com/privacy",
      "security_url": "https://account.adobe.com/security"
    }
  ]
}
```

The summary is there so the model reports coverage honestly ("8 found, 4 couldn't be checked") rather than implying a complete result.

### Client setup

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "footprint": {
      "command": "footprint-mcp"
    }
  }
}
```

Claude Code:

```bash
claude mcp add footprint -- footprint-mcp
```

Example prompts:

- "Find every account tied to someone@example.com."
- "Which of those accounts are shopping sites?"
- "Retry the ones that got rate limited."

---

## Distribution

Releases are built and published with **GoReleaser** on tag push via GitHub Actions:

- Binaries for darwin/linux/windows on amd64/arm64
- Homebrew formula auto-updated in `idrewlong/homebrew-tap`
- Checksums and SBOM attached to each release

```bash
brew install idrewlong/tap/footprint   # installs footprint and footprint-mcp
go install github.com/idrewlong/footprint/cmd/...@latest
```

---

## Roadmap

**v0.1: core**
- [x] `pkg/checker` engine with concurrency, timeouts, and streaming results
- [x] 15 to 20 high-value sites with fixtures (Google, Apple, Microsoft, Amazon, GitHub, Adobe, Spotify, Twitter/X, Instagram, Discord, etc.)
- [x] CLI with table and JSON output

**v0.2: MCP**
- [x] `footprint-mcp` over stdio with all three tools
- [x] Delete and security URLs for every supported site
- [ ] GoReleaser + Homebrew tap

**v0.3: TUI**
- [ ] Bubble Tea interface with live table, filters, open-in-browser, export

**v0.4: coverage**
- [ ] 100+ sites
- [ ] Nightly live-check job that opens an issue when a site check breaks
- [ ] Markdown cleanup-report export

---

## Contributing a site

1. Add `pkg/sites/<name>.go` implementing `Site`.
2. Record fixtures in `testdata/<name>/`: `found.http`, `not_found.http`, `rate_limited.http`.
3. Add `DeleteURL` and `SecurityURL` if the site has them.
4. Run `go test ./pkg/sites/ -run <Name>`.
5. Open a PR. Checks that trigger notification emails to the account owner will not be accepted.

---

## License

To be decided before the first release:

- **GPL-3.0**, if any site checks are translated from Holehe's modules (a derivative work must carry Holehe's license)
- **MIT**, if every check is written independently from direct inspection of each site, using Holehe only as a reference for which sites to cover

## Acknowledgments

Inspired by [Holehe](https://github.com/megadose/holehe) by megadose.