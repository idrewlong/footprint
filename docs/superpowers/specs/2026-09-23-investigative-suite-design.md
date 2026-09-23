# Investigative suite

Footprint becomes a local case workstation. One binary runs public-source checks and writes a case note an analyst can defend. The MCP server is a later reader of those notes. It is not part of the first implementation pass.

## Already built

Email and username scans, breach-name checks, the `Evidence` field, and the markdown case note (bottom line, findings, coverage, actions) stay as they are. This design adds modules beside them. It does not replace `pkg/sites` or `pkg/profiles`.

## What a run answers

| Command | Question | Source |
|---|---|---|
| `footprint scan email` / `scan username` | Which sites show this email or username? | Existing site and profile checks |
| `footprint lookup domain` | Is this a real mailbox domain, and what do its mail records say? | The machine's DNS resolver. Certificate search is opt-in |
| `footprint lookup ip` | What network is this address on? | Reverse DNS, Team Cymru's public ASN zone, a local GeoIP database, RDAP |
| `footprint lookup entity` | Does this organization name match a public list? | A local OFAC SDN file the user supplies, and the SEC company-tickers file |
| `footprint diff` | What changed between two saved reports? | Local JSON only |
| `footprint note` | One case note from several saved reports | Local JSON only |

Each hit carries an evidence sentence naming the source. `rate_limited` and `error` stay distinct from `not_found`. A missing database, a missing sanctions file, a timeout, or an empty response is `error` or a usage error. It is never a clean miss.

## Sends

Checks run on the user's machine.

- Domain lookup sends the domain name to the configured DNS resolver. The mailbox local-part is stripped first and is never sent.
- `--certs` also sends the domain to `crt.sh`. Without the flag, crt.sh is not contacted.
- IP lookup sends a public IP to Team Cymru DNS and to `https://rdap.org/ip/<ip>`. The evidence sentence names those sources. Private, loopback, link-local, unspecified, multicast, carrier-grade NAT (`100.64.0.0/10`), and documentation (`2001:db8::/32`) addresses are not sent. Reverse DNS for those addresses still runs on the local resolver.
- City comes from a MaxMind GeoLite2 City database the user already has. The tool does not download it. The evidence sentence says this is the network's city, not a person or a street address. Latitude and longitude are not printed.
- Entity lookup sends the organization name to `https://www.sec.gov/files/company_tickers.json` with a descriptive User-Agent. OFAC screening reads a local CSV and does not send the name anywhere.
- Nothing in this design sends an email address except the existing site checks, which send it only to the site being checked.

## Case files

`--save` writes a JSON report under `~/.local/share/footprint/` with mode `0600`. Directories are created with mode `0700`. The path is printed on stderr. Stdout stays the report.

`diff` compares two saved reports by site and method:

- **Added:** found now, and the earlier row was missing or `not_found`.
- **Gone:** found before, and the later row is `not_found`.
- **Unchecked:** found before, and the later row is `rate_limited`, `error`, or missing. These are not described as deleted.
- **Still:** found in both.

## Case note

`lookup` writes the same shape as a scan: a `report.Document` of `checker.Result` rows, rendered as a terminal report, JSON, or the markdown case note.

Rows with method `dns`, `infra`, or `entity` get their own sections. They are not counted as email matches. Identity rows keep the current ranking: email match, breach name, public profile, mailbox-derived username.

`footprint note a.json b.json` merges saved reports into one document. It refuses to merge two reports whose email, username, domain, IP, or entity subject disagree.

After an email scan, if a found profile row has a profile URL and the user did not already pass a username, stderr prints one suggested command: `footprint scan username <name>`. The tool does not run it.

## MCP, after the local gate

`cmd/footprint-mcp` is implemented only after `go test ./...` passes for the local modules with no network. Tools, stdio only:

| Tool | Input | Returns |
|---|---|---|
| `scan_email` | `email`, optional `categories`, `only_found` | Summary counts plus results |
| `lookup_domain` | `domain`, optional `certs` | Summary counts plus results |
| `lookup_ip` | `ip` | Summary counts plus results |
| `lookup_entity` | `name`, `sdn_path` | Summary counts plus results |
| `diff_reports` | `old_path`, `new_path` | Added, gone, unchecked, still |
| `list_sites` | optional `category` | Site name, domain, category, method |

There is no tool that searches for a person, resolves an IP to a household, or reads tax or property records. HTTP transport is out of this design. If it is added later, it binds to `127.0.0.1` unless the user explicitly overrides it.

## Out of scope

- Login, submitted passwords, or credential checks.
- Breach contents. Breach checks still return names only.
- People search, IP-to-person resolution, tax records, and property-roll matching.
- Passive DNS. Maintained sources need a vendor key and a separate design.
- OpenCorporates. Same reason.
- Fuzzy name matching. Entity and sanctions matches are exact after normalization.
- A hosted lookup service, telemetry, or a download of the GeoIP database.

## Failure modes the tests must pin

- A DNS timeout or SERVFAIL is `error`, not `not_found`.
- A missing GeoIP database does not produce a city.
- A missing OFAC file does not produce "not sanctioned."
- `diff` does not call a `rate_limited` or missing re-check a deletion.
- GeoIP evidence does not name a person or a street, and does not include coordinates.
- A private IP never reaches Team Cymru or RDAP.
- An entity query that is an email address or an IP is a usage error, not a search.
- Saved reports are mode `0600`.
- The mailbox local-part never reaches the DNS resolver.
