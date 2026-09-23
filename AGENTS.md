# footprint

Open-source Go OSINT tool. Given an email, it reports which sites have an account, using public signup, login, and password-reset signals. One static binary, three front ends, one engine.

Design detail lives in `project-overview.md`. Follow that document when this file and the overview disagree on structure. This file wins on the constraints below.

## Boundaries

- Checks run on the user's machine. Do not add a hosted lookup service, telemetry, or any path that sends the email anywhere except the site being checked.
- Do not log in, submit passwords, or check credentials.
- A breach check may report the names of known breaches that include the email. Do not return passwords, hashes, or other stolen values.
- Password-reset checks are allowed. They may email the address being checked. Do not create an account.
- Never report a miss when the real outcome is unknown. `rate_limited` and `error` stay distinct from `not_found`.
- Do not copy Holehe modules. Use Holehe only as a list of sites worth covering. Each check is written from the site's own public behavior. License is undecided until the first release; copying Holehe code would force GPL-3.0.

## Layout

Site logic lives only in `pkg/sites/`, one file per site, registered in `init`. `cmd/footprint`, the TUI, and `cmd/footprint-mcp` call `pkg/checker` and render `Result` values. They do not know how a site is checked.

| Path | Owns |
|---|---|
| `pkg/checker` | Concurrency, per-check timeouts, streaming results, per-domain backoff |
| `pkg/sites` | `Site` implementations |
| `pkg/report` | JSON, table, and markdown rendering |
| `internal/httpx` | Shared client, user-agent rotation, cookie jar |
| `testdata/<site>/` | Recorded HTTP fixtures |
| `cmd/footprint` | CLI and Bubble Tea TUI |
| `cmd/footprint-mcp` | MCP server (`scan_email`, `check_site`, `list_sites`) |

Statuses are `found`, `not_found`, `rate_limited`, and `error`. Methods are `register`, `login`, `password_reset`, and `breach`. A found account should include `delete_url` and `security_url` when the site has those pages. A breach hit lists breach names in `detail` and does not include stolen values.

Default engine limits: 16 concurrent checks, 10s timeout each, overridable with `--concurrency`. A 429 or a known block page is `rate_limited`, not `not_found`.

## Adding a site

1. Add `pkg/sites/<name>.go` implementing `Site`.
2. Record `testdata/<name>/found.http`, `not_found.http`, and `rate_limited.http`.
3. Set delete and security URLs when they exist.
4. Test with `go test ./pkg/sites/ -run <Name>`. Fixture tests must not hit the network. Live checks belong in the separate, manually triggered `live` job.

## Build order

Ship in roadmap order. Do not start the TUI, the MCP server, or the 100-site push while `pkg/checker` and the first CLI sites are unfinished.

1. **v0.1** checker, 15–20 sites with fixtures, CLI table and JSON.
2. **v0.2** `footprint-mcp` on stdio, delete and security URLs, GoReleaser.
3. **v0.3** Bubble Tea TUI.
4. **v0.4** 100+ sites, nightly live-check job, markdown export.

MCP HTTP transport, if added, binds to localhost unless the user explicitly overrides it. `scan_email` returns summary counts plus results so a partial run is not described as complete.
