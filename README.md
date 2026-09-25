# footprint

[![ci](https://github.com/idrewlong/footprint/actions/workflows/ci.yml/badge.svg)](https://github.com/idrewlong/footprint/actions/workflows/ci.yml)

Find accounts registered to an email address, and public profiles for a username. `footprint scan email` checks that address. `footprint scan username` checks public profiles. Pass both arguments to run the two together. An email scan includes breach names from XposedOrNot, LeakCheck, and Have I Been Pwned when `HIBP_API_KEY` is set. Breach checks list names and do not return passwords or other stolen values. The tool does not log in or submit a password. `footprint sites` lists every check, with its category and method.

## Limitations

A result is what one public signal said. `not_found` on a site is not proof that no account exists, and the site list is not exhaustive.

- Checks run on your machine. The email is sent only to the site being checked. There is no hosted lookup and no telemetry.
- The tool does not log in, submit a password, or create an account. A breach hit is a list of breach names. Passwords, hashes, and other stolen values are not requested or shown.
- Password-reset checks can email the address. They run only when you pass `--allow-notify`. No password-reset checks ship yet, so today the flag changes nothing.
- Statuses are `found`, `not_found`, `rate_limited`, and `error`. A timeout, a block page, or a response that does not say whether the account exists is `rate_limited` or `error`. It is never reported as `not_found`.
- Have I Been Pwned runs only when `HIBP_API_KEY` is set. Without it, that one row is an error and the rest of the scan still runs. XposedOrNot and LeakCheck do not need a key.
- `lookup ip` covers IPv4 and IPv6. Reverse DNS, ASN, RDAP, and the published range lists need no extra file. A city requires a GeoLite2 City database you download; footprint does not fetch it. The city is the network's location, not a person or a street address. Private and documentation addresses are not sent to Team Cymru or RDAP.
- `--proxy` applies to `scan`, `user`, `probe`, and the MCP server. `lookup` does not take it, so a domain, IP, or organization lookup leaves from your own address.
- `lookup entity` compares the name with the primary names in an OFAC SDN CSV you supply. Case and punctuation are ignored, so `APPLE, INC.` matches `Apple Inc.` Extra words do not: `Apple` does not match `Apple Inc.` Alias and address files are not read. An email address or an IP is rejected. Without `--sdn`, the OFAC row is an error, not a clear miss.
- A published range list that could not be loaded is named. That address is not reported as absent from a list the tool did not read.

## Install

Clone the repo and build it. Building needs Go (the version in `go.mod`) and nothing else. A scan, a username check, and an IP lookup without a city need no API key and no extra file.

```bash
git clone https://github.com/idrewlong/footprint.git
cd footprint
go build -o footprint ./cmd/footprint
go build -o footprint-mcp ./cmd/footprint-mcp
./footprint scan email me@example.com
```

Or install both binaries into `$GOPATH/bin` without cloning:

```bash
go install github.com/idrewlong/footprint/cmd/...@latest
```

Prebuilt archives for Linux, macOS, and Windows (amd64 and arm64) are also on the GitHub releases page, each with an SPDX SBOM and a cosign-signed checksum file, for anyone without Go.

### Verifying a release

`checksums.txt` covers every archive and SBOM, and is signed keylessly by this repository's release workflow:

```bash
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/idrewlong/footprint/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
shasum -a 256 --ignore-missing -c checksums.txt
```

Builds are reproducible. From the tagged checkout, with the Go version in `go.mod`, this produces a binary byte-identical to the one in the release archive for that platform:

```bash
git checkout v0.2.0
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -buildid=" ./cmd/footprint
```

## Usage

```bash
footprint scan email me@example.com
footprint scan username octocat
footprint scan email me@example.com username octocat
footprint sites
footprint sites --category dev
footprint probe github test@gmail.com
footprint lookup domain example.com
footprint lookup ip 8.8.8.8
footprint lookup ip "2600:1700:aded:6010:40a6:6ab0:9078:22ec"
```

The word after `lookup` is the kind: `domain`, `ip`, or `entity`. `footprint lookup 8.8.8.8` is rejected. Quote an IPv6 address so the shell keeps it as one argument.

The terminal lists found accounts. Each hit shows the method and the sentence for the signal that check used. Each breach name is on its own line. The summary still counts found, not found, rate limited, and error, so a partial run is not reported as complete. `--json` includes every status. `--md` writes a one-page case note: a bottom line, findings strongest first, coverage, and actions. `--only-found` drops non-hits from the JSON export. The case note still lists rate-limited and error rows as unchecked.

`footprint scan username` checks public profile URLs. A hit includes the profile link. It does not collect a location, email address, or company. `footprint user` is the same check. If an email scan finds a public profile URL with a single path segment, stderr prints a suggested `footprint scan username` command. The tool does not run that scan.

`footprint probe <site> <email>` runs that one check through the same client a scan uses and prints the raw status, headers, and body. A password-reset site still needs `--allow-notify`.

A 429 or a known block page is `rate_limited`. A response that does not clearly say whether the address is registered is `error`. Neither is reported as `not_found`.

**Passive by default.** No check contacts the subject. Password-reset checks, the only method that can email the address under investigation, run only when you pass `--allow-notify`; without it they are skipped and named on stderr.

**Confidence.** Each found row is rated `high`, `medium`, or `low`. A signup or login lookup is high; a breach corpus or a profile matched from a username you gave is medium; a profile matched only from the mailbox name is low. The rating is in `--json` and the Markdown findings table.

**Breach timeline.** When a breach source reports dates (metadata, never stolen values), the case note lists breaches oldest first. Passwords, hashes, and other stolen values are never requested or shown.

**Routing.** `--proxy` sends every request through a proxy, so a scan need not go out from an identifiable IP. It accepts `http`, `https`, `socks5`, and `socks5h`; for Tor, use `--proxy socks5h://127.0.0.1:9050`. A bad proxy is a hard error, so traffic never silently falls back to your own address.

**Batch.** `--batch <file>` reads one subject per line (`#` comments and blanks ignored, duplicates collapsed) and scans them in one run. The kind comes from the keyword: `footprint scan email --batch list.txt` or `footprint scan username --batch handles.txt`. Invalid lines are named on stderr and skipped, never counted as a result. `--json` emits one array of reports.

### Domain, IP, and organization

```bash
footprint lookup domain ada@example.com
footprint lookup domain example.com --certs
footprint lookup ip 8.8.8.8
footprint lookup ip "2600:1700::1"
footprint lookup ip 8.8.8.8 --geoip ~/GeoLite2-City.mmdb
footprint lookup entity "Apple Inc." --sdn ~/SDN.CSV
```

`~/GeoLite2-City.mmdb` and `~/SDN.CSV` are paths you choose after downloading those files. They are not in this repository. Passing a path that does not exist does not search for a copy elsewhere.

`lookup domain` checks MX, SPF, DMARC, and a local disposable-domain list. If you pass an email, DNS sees only the part after `@`. `--certs` also asks crt.sh how many certificates name that domain. Without the flag, crt.sh is not contacted.

`lookup ip` prints a summary panel for the address: hostname and whether it resolves back to the address, ASN and AS name (IPv4 and IPv6), announced prefix, RDAP network and organization, and, when you pass a MaxMind GeoLite2 City database with `--geoip`, city, region, postal code, country, time zone, and coordinates with the database's accuracy radius. Coordinates are shown only with that radius. The panel also flags addresses in published range lists: AWS, Google Cloud, Azure, Oracle Cloud, DigitalOcean, Cloudflare, Fastly, the Tor exit list, and the community X4BNet VPN list. Whole lists are downloaded to your cache directory and matched locally, so the address is never sent to them. Lists refresh daily (Tor hourly); `--no-update` uses the cached copies only. A list that could not be loaded is named, and a miss is not reported as complete. The same fields are under `ip` in `--json`. The location is the network's, not a person's or a street address. Private and documentation addresses are not sent to Team Cymru or RDAP.

The GeoIP database is a file you download. Create a MaxMind account at [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup), download **GeoLite2 City** in MMDB format (GeoIP2 Binary), and pass that `.mmdb` file to `--geoip`. Leave the flag off to run the lookup without a city: the geoip row is then an error (`geoip database not configured`) and the ASN and RDAP rows still run. A path that does not open stops the command before any lookup.

`lookup entity` matches the name against a local OFAC SDN CSV (`--sdn`) and the SEC company-tickers list, which is fetched from sec.gov. Download the primary-names file, `SDN.CSV`, from [OFAC's Sanctions List Service](https://ofac.treasury.gov/sanctions-list-service). The tool reads that file only. It does not load `ALT.CSV` (aliases) or `ADD.CSV` (addresses). An email address or an IP is rejected. Without `--sdn`, the OFAC row is an error (`sanctions list not configured`) and the SEC check still runs. A path that does not open is named on stderr and the OFAC row is an error; it is not a clear miss. `Apple` does not match `Apple Inc.`

Each lookup accepts `--json`, `--md`, `--timeout` (default 10s), `--save`, `--case-dir`, `--case-id`, and `--authority`. `--save` requires `--case-id` and `--authority`, and a lookup without them is refused before anything is sent.

### Case files

```bash
footprint scan email me@example.com --save --case-dir ./cases --case-id C-2026-001 --authority "warrant 24-1234"
footprint lookup domain example.com --save --case-dir ./cases --case-id C-2026-001 --authority "warrant 24-1234"
footprint keygen
footprint verify --case-dir ./cases --head <hash from the last save>
footprint diff old.json new.json
footprint note a.json b.json
footprint note a.json b.json --json
```

`--save` writes the full report, including misses, as mode `0600` under `--case-dir` (default `~/.local/share/footprint`). The path is printed on stderr as `saved <path>`. Stdout stays the report. `diff` and `note` read those saved files. A JSON file produced with `--json` and a redirect is not a case file.

**Purpose and authority.** A saved case must carry `--case-id` and `--authority`, so every durable record is tied to the case and the legal basis for the lookup. The operator name (from `FOOTPRINT_OPERATOR`, `USER`, or `LOGNAME`) is recorded with it. Unsaved runs are not gated.

**Tamper-evident audit ledger.** Each save is appended to a signed, append-only ledger (`audit.log`) in the case directory. Every entry records the case, authority, operator, tool version, and a SHA-256 of the saved file, and commits to the previous entry's hash, forming a chain. Entries are signed with an Ed25519 key that is kept **outside** the case directory, at `FOOTPRINT_SIGN_KEY` or the user config directory (`footprint keygen` creates it and prints where it is and its fingerprint). A save refuses a key inside the case directory, because whoever can edit the ledger could then re-sign it.

`footprint verify` re-checks every saved file against its recorded hash, confirms the chain links, and checks each signature against a public key *you* trust: `--pubkey <file>` (repeatable), or by default the `.pub` beside your own signing key. The key written inside the ledger is never trusted on its own, so a chain rebuilt under a different key fails. With no trusted key available, `verify` fails rather than passing. A chain cannot show that entries were cut from its end, so each save prints the ledger head on stderr (`audit head <hash>`) and `verify` prints it too; record it somewhere independent and pass `--head <hash>` to confirm it is still in the ledger. `verify` exits non-zero on any problem.

Ledgers written before the key moved were signed with `footprint-ed25519.key` inside the case directory. Verifying them means trusting that key explicitly with `--pubkey <case-dir>/footprint-ed25519.pub`, with the weaker guarantee that implies.

`diff` prints four sections. Added means found now and not found before. Gone means found before and `not_found` now. Unchecked means it was found before and the new row is rate limited, an error, or missing. Still is the count of hits in both files.

`note` merges saved reports into one case note. Markdown is the default. Pass `--json` for the merged document. Two reports that name a different email, username, domain, IP, or organization are refused. The same site in both files keeps the later row. Domain, network, and organization hits are in their own sections. They are not counted as email matches.

### Export for analyst tools

```bash
footprint export case.json --format graphml --out case.graphml
footprint export email.json domain.json --format stix --out case.stix.json
footprint export case.json --format neo4j    # also: misp, maltego
```

`export` builds a pivot graph from one or more saved case files — email → username → accounts → profiles → domain → IP → organization, plus breach nodes — and writes it in the format your tools read: **GraphML** (yEd, Gephi, Neo4j import), a Neo4j nodes-and-relationships **JSON**, a **STIX 2.1** bundle of Cyber Observables and relationships, a **MISP** event, or **Maltego** entity CSV. Several case files are merged first, so an email case and a domain case export as one connected graph. Exports carry breach names and dates but never a password, hash, or other stolen value. STIX identifiers are derived from the graph, so re-exporting the same case yields an identical bundle.

## MCP server

`footprint-mcp` lets an AI assistant such as Claude run checks over the Model Context Protocol, on stdio. It runs on your machine, like the CLI.

```bash
claude mcp add footprint -- footprint-mcp
```

Claude Desktop (`claude_desktop_config.json`):

```json
{ "mcpServers": { "footprint": { "command": "footprint-mcp" } } }
```

| Tool | Input | Returns |
|---|---|---|
| `scan_email` | `email`, `categories?`, `only_found?` | Summary counts, `complete`, a one-line coverage `note`, and one result per site |
| `check_site` | `email`, `site` | One result, for retrying a rate-limited site |
| `list_sites` | `category?` | Sites with category, method, and whether the check can email the address |

`complete` is false whenever a check was rate limited, errored, or skipped, and the `note` says those accounts are unknown, not absent, so the assistant cannot present a partial run as finished.

Policy is set when the server starts, not by the assistant: `--allow-notify` (checks that can email the address), `--proxy`, `--concurrency`, `--timeout`, and `--save --case-id <id> --authority <text> [--case-dir path]`. With `--save`, every `scan_email` is written to the case directory and signed into the audit ledger, and the result includes `saved_to` and `audit_head`. For example:

```bash
claude mcp add footprint -- footprint-mcp --proxy socks5h://127.0.0.1:9050 --save --case-id C-2026-001 --authority "warrant 24-1234"
```

## Environment

A scan, a username check, `probe`, and `lookup domain` or `lookup ip` without `--geoip` need none of these.

| Variable | Effect |
|---|---|
| `HIBP_API_KEY` | Have I Been Pwned API key, from [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key). Unset, the hibp row is an error (`hibp api key required`) and every other check still runs. |
| `FOOTPRINT_OPERATOR` | Name stored with `--save`. If unset, `USER`, then `LOGNAME`. |
| `FOOTPRINT_SIGN_KEY` | Path to the audit signing key. If unset, the key lives in the user config directory. `footprint keygen` creates it and prints the path and fingerprint. |
| `NO_COLOR` | Set to any value to turn off color when stdout is a terminal. |

GeoIP and the SDN list are files you pass with `--geoip` and `--sdn`, not environment variables. See the lookup section for where to download them.

The manually triggered live job also reads `FOOTPRINT_LIVE_CANARY_EMAIL`, `FOOTPRINT_LIVE_CANARY_SITES`, and `FOOTPRINT_LIVE_ALLOW_NOTIFY=1` (password-reset checks). Those are for that job, not for a local scan. See Development.

## Development

```bash
go test -race ./...     # fixture tests; never touch the network
go test -tags live -run '^TestLive(UnregisteredAddress|Canary)$' -v ./pkg/sites/   # hits real sites
```

CI runs gofmt, `go mod tidy`, `go vet`, `go test -race`, `govulncheck`, and `goreleaser check` on every push and pull request. The live checks run only from the manually triggered `live` workflow: each site is checked with a random address (found or error fails; rate limited is skipped). Set the `FOOTPRINT_LIVE_CANARY_EMAIL` secret and `FOOTPRINT_LIVE_CANARY_SITES` variable to also confirm an address you control is still found, which catches a check that always says not found. Pushing a `v*` tag runs GoReleaser, which publishes the prebuilt archives to GitHub Releases; it needs no secrets beyond the workflow's own token.

## Layout

Site checks live in `pkg/sites/`, one file per site. The CLI (`cmd/footprint`) and the MCP server (`cmd/footprint-mcp`) call `pkg/checker` and render results with `pkg/report`. Case files, the audit ledger, and `verify` live in `pkg/casefile`; the pivot graph and its exporters live in `pkg/graph`.

### Adding a site

1. Add `pkg/sites/<name>.go` implementing `checker.Site`, registered in `init`. Write the check from the site's own public behavior; do not copy another tool's modules.
2. Record `testdata/<name>/found.http`, `not_found.http`, and `rate_limited.http`. A fixture holds one or more raw HTTP responses separated by a line containing `---`, one per request the check makes.
3. Set the delete and security URLs when the site has those pages.
4. Run `go test ./pkg/sites/ -run <Name>`. Fixture tests never touch the network.
5. Run `footprint probe <name> <email>` to see what the live site returns through the real client, and confirm a random address comes back `not_found`, not `found` or `error`.

A check that cannot tell whether the account exists returns `rate_limited` or `error`, never `not_found`. Do not add a check that needs a CAPTCHA, logs in, or creates an account.

## License

MIT. See [LICENSE](LICENSE).

Inspired by [Holehe](https://github.com/megadose/holehe) by megadose. footprint shares no code with it; each check is written from the site's own public behavior.
