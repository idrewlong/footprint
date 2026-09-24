# footprint

Find accounts registered to an email address, and public profiles for a username. `footprint scan email` checks that address. `footprint scan username` checks public profiles. Pass both arguments to run the two together. An email scan includes breach names from XposedOrNot, LeakCheck, and Have I Been Pwned when `HIBP_API_KEY` is set. Breach checks list names and do not return passwords or other stolen values. The tool does not log in or submit a password. A password-reset check may email the address being checked when that site's response shows whether the account exists.

## Install

```bash
go install github.com/idrewlong/footprint/cmd/footprint@latest
```

From a checkout:

```bash
go build -o footprint ./cmd/footprint
```

## Usage

```bash
footprint scan email me@example.com
footprint scan username octocat
footprint scan email me@example.com username octocat
footprint sites
footprint sites --category dev
```

The terminal lists found accounts. Each hit shows the method and the sentence for the signal that check used. Each breach name is on its own line. The summary still counts found, not found, rate limited, and error, so a partial run is not reported as complete. `--json` includes every status. `--md` writes a one-page case note: a bottom line, findings strongest first, coverage, and actions. `--only-found` drops non-hits from the JSON export. The case note still lists rate-limited and error rows as unchecked.

`footprint scan username` checks public profile URLs. A hit includes the profile link. It does not collect a location, email address, or company. `footprint user` is the same check. If an email scan finds a public profile URL with a single path segment, stderr prints a suggested `footprint scan username` command. The tool does not run that scan.

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
footprint lookup ip 8.8.8.8 --geoip GeoLite2-City.mmdb
footprint lookup entity "Apple Inc." --sdn sdn.csv
```

`lookup domain` checks MX, SPF, DMARC, and a local disposable-domain list. If you pass an email, DNS sees only the part after `@`. `--certs` also asks crt.sh how many certificates name that domain. Without the flag, crt.sh is not contacted.

`lookup ip` prints a summary panel for the address: hostname and whether it resolves back to the address, ASN and AS name (IPv4 and IPv6), announced prefix, RDAP network and organization, and, when you pass a MaxMind GeoLite2 City database with `--geoip`, city, region, postal code, country, time zone, and coordinates with the database's accuracy radius. Coordinates are shown only with that radius. The panel also flags addresses in published range lists: AWS, Google Cloud, Azure, Oracle Cloud, DigitalOcean, Cloudflare, Fastly, the Tor exit list, and the community X4BNet VPN list. Whole lists are downloaded to your cache directory and matched locally, so the address is never sent to them. Lists refresh daily (Tor hourly); `--no-update` uses the cached copies only. A list that could not be loaded is named, and a miss is not reported as complete. The same fields are under `ip` in `--json`. The location is the network's, not a person's or a street address. The tool does not download the database. Private and documentation addresses are not sent to Team Cymru or RDAP. A missing database is an error, not a guessed city.

`lookup entity` matches the name exactly against a local OFAC SDN CSV (`--sdn`) and the SEC company-tickers list. An email address or an IP is rejected. A missing or unreadable SDN file is an error on stderr, not a clear miss. `Apple` does not match `Apple Inc.`

Each lookup accepts `--json`, `--md`, `--timeout` (default 10s), `--save`, and `--case-dir`.

### Case files

```bash
footprint scan email me@example.com --save --case-dir ./cases --case-id C-2026-001 --authority "warrant 24-1234"
footprint lookup domain example.com --save --case-dir ./cases --case-id C-2026-001 --authority "warrant 24-1234"
footprint verify --case-dir ./cases
footprint diff old.json new.json
footprint note a.json b.json
footprint note a.json b.json --json
```

`--save` writes the full report, including misses, as mode `0600` under `--case-dir` (default `~/.local/share/footprint`). The path is printed on stderr as `saved <path>`. Stdout stays the report. `diff` and `note` read those saved files. A JSON file produced with `--json` and a redirect is not a case file.

**Purpose and authority.** A saved case must carry `--case-id` and `--authority`, so every durable record is tied to the case and the legal basis for the lookup. The operator name (from `FOOTPRINT_OPERATOR`, `USER`, or `LOGNAME`) is recorded with it. Unsaved runs are not gated.

**Tamper-evident audit ledger.** Each save is appended to a signed, append-only ledger (`audit.log`) in the case directory. Every entry records the case, authority, operator, tool version, and a SHA-256 of the saved file, and commits to the previous entry's hash, forming a chain. Entries are signed with a local Ed25519 key (`footprint-ed25519.key`, mode `0600`, generated on first save). `footprint verify` re-checks every saved file against its recorded hash, confirms the chain links, and verifies each signature — so you can show a case file, and the order of a case's steps, have not been altered. It exits non-zero on any problem.

`diff` prints four sections. Added means found now and not found before. Gone means found before and `not_found` now. Unchecked means it was found before and the new row is rate limited, an error, or missing. Still is the count of hits in both files.

`note` merges saved reports into one case note. Markdown is the default. Pass `--json` for the merged document. Two reports that name a different email, username, domain, IP, or organization are refused. The same site in both files keeps the later row. Domain, network, and organization hits are in their own sections. They are not counted as email matches.

### Export for analyst tools

```bash
footprint export case.json --format graphml --out case.graphml
footprint export email.json domain.json --format stix --out case.stix.json
footprint export case.json --format neo4j    # also: misp, maltego
```

`export` builds a pivot graph from one or more saved case files — email → username → accounts → profiles → domain → IP → organization, plus breach nodes — and writes it in the format your tools read: **GraphML** (yEd, Gephi, Neo4j import), a Neo4j nodes-and-relationships **JSON**, a **STIX 2.1** bundle of Cyber Observables and relationships, a **MISP** event, or **Maltego** entity CSV. Several case files are merged first, so an email case and a domain case export as one connected graph. Exports carry breach names and dates but never a password, hash, or other stolen value. STIX identifiers are derived from the graph, so re-exporting the same case yields an identical bundle.

## Layout

Site checks live in `pkg/sites/`, one file per site. The CLI calls `pkg/checker` and renders results with `pkg/report`. Case files, the audit ledger, and `verify` live in `pkg/casefile`; the pivot graph and its exporters live in `pkg/graph`. Adding a site is described in `AGENTS.md`.
