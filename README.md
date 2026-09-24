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
footprint scan email me@example.com --json
footprint scan email me@example.com --md > audit.md
footprint scan email me@example.com --save --case-dir ./cases
footprint sites
footprint sites --category dev
footprint lookup domain ada@example.com
footprint lookup domain example.com --certs
footprint lookup ip 8.8.8.8
footprint lookup entity "Apple Inc." --sdn sdn.csv
footprint diff old.json new.json
footprint note a.json b.json --md
```

The terminal lists found accounts. Each hit shows the method and the sentence for the signal that check used. Each breach name is on its own line. The summary still counts found, not found, rate limited, and error, so a partial run is not reported as complete. `--json` includes every status. `--md` writes a one-page case note: a bottom line, findings strongest first, coverage, and actions. `--only-found` drops non-hits from the JSON export. The case note still lists rate-limited and error rows as unchecked. `--save` writes a 0600 case file under `--case-dir` (default `~/.local/share/footprint`) and prints `saved <path>` on stderr.

`footprint scan username` checks public profile URLs. A hit includes the profile link. It does not collect a location, email address, or company. `footprint user` is the same check.

`footprint lookup domain` checks MX, SPF, DMARC, and a local disposable list for the domain; when the argument is an email, only the part after `@` is used for DNS. `footprint lookup ip` describes a network (PTR, ASN, optional GeoIP, RDAP), not a person. `footprint lookup entity` is an exact public-list match against a local OFAC SDN file and the SEC company tickers list. `footprint diff` compares two saved reports. `footprint note` merges saved reports into one case note (Markdown by default).

A 429 or a known block page is `rate_limited`. A response that does not clearly say whether the address is registered is `error`. Neither is reported as `not_found`.

## Layout

Site checks live in `pkg/sites/`, one file per site. The CLI calls `pkg/checker` and renders results with `pkg/report`. Adding a site is described in `AGENTS.md`.
