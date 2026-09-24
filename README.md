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
footprint scan email me@example.com --save --case-dir ./cases
footprint lookup domain example.com --save --case-dir ./cases
footprint diff old.json new.json
footprint note a.json b.json
footprint note a.json b.json --json
```

`--save` writes the full report, including misses, as mode `0600` under `--case-dir` (default `~/.local/share/footprint`). The path is printed on stderr as `saved <path>`. Stdout stays the report. `diff` and `note` read those saved files. A JSON file produced with `--json` and a redirect is not a case file.

`diff` prints four sections. Added means found now and not found before. Gone means found before and `not_found` now. Unchecked means it was found before and the new row is rate limited, an error, or missing. Still is the count of hits in both files.

`note` merges saved reports into one case note. Markdown is the default. Pass `--json` for the merged document. Two reports that name a different email, username, domain, IP, or organization are refused. The same site in both files keeps the later row. Domain, network, and organization hits are in their own sections. They are not counted as email matches.

## Layout

Site checks live in `pkg/sites/`, one file per site. The CLI calls `pkg/checker` and renders results with `pkg/report`. Adding a site is described in `AGENTS.md`.
