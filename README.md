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
footprint sites
footprint sites --category dev
```

The terminal lists found accounts. Each breach name is on its own line. The summary still counts found, not found, rate limited, and error, so a partial run is not reported as complete. `--json` and `--md` include every status. `--only-found` drops non-hits from those exports only.

`footprint scan username` checks public profile URLs. A hit includes the profile link. It does not collect a location, email address, or company. `footprint user` is the same check.

A 429 or a known block page is `rate_limited`. A response that does not clearly say whether the address is registered is `error`. Neither is reported as `not_found`.

## Layout

Site checks live in `pkg/sites/`, one file per site. The CLI calls `pkg/checker` and renders results with `pkg/report`. Adding a site is described in `AGENTS.md`.
