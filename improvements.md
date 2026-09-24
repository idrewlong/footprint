# Improvements

Ideas for footprint beyond the roadmap in `project-overview.md`. Every item stays within the boundaries in `AGENTS.md`: checks run locally, nothing logs in, no stolen values are returned, and an unknown outcome is never `not_found`.

Items are grouped by the milestone they fit best. The last section holds items that can land any time after v0.1.

## Now: finish v0.1

- [x] Make a first commit so CI and GoReleaser have history to work from.
- [ ] Update `project-overview.md` to cover `pkg/profiles`, the `footprint user` command, and the `breach` method.
- [ ] List all four methods (`register`, `login`, `password_reset`, `breach`) in the comment on `Result.Method`.
- [x] Resolve the policy conflict. Scans are now passive by default: password-reset (notifying) checks run only with `--allow-notify` (`checker.Notifies`, gated in the CLI). Still to do: reconcile the wording in `project-overview.md` step 5 and `AGENTS.md`.
- [x] Add an `Evidence` field to `Result` that records the signal a check relied on, such as "signup endpoint said 'email already in use'". Fill it in for every existing site and fixture test.
- [x] Skip checks that email the target by default (the `password_reset` methods); include them only with `--allow-notify`. (supersedes the proposed opt-out `--quiet`)

## v0.2: MCP

- [ ] Retry `rate_limited` checks once, with jittered backoff per domain, before settling on the final status.
- [ ] Add `footprint retry <report.json>`, which re-runs only the `rate_limited` and `error` rows from an earlier JSON report.
- [x] Link breaches to found accounts. When a breach name matches a site that came back `found`, list that account first with a note to change the password and turn on 2FA, linking its `security_url`.
- [ ] Run `govulncheck` in CI.
- [ ] Sign release artifacts with cosign.
- [ ] Make builds reproducible and document how to verify them.

## v0.3: TUI

- [ ] Save each scan to a local history directory, such as `~/.local/share/footprint/`.
- [ ] Add `footprint diff <old> <new>` to report new accounts, new breaches, and accounts that are gone, so a deletion can be confirmed.
- [ ] Document running scans on cron as local-only monitoring.
- [ ] Render found accounts in the markdown export as a checkbox list with delete and security links.
- [ ] Add a deletion difficulty rating (easy, medium, hard, impossible) to each site.
- [ ] Provide GDPR and CCPA request templates for sites with no delete page.

## v0.4: 100+ sites

- [ ] For each site, keep one canary address known to have an account and one random address known not to. The live job checks that the first returns `found` and the second `not_found`, which catches checks that break by always returning `not_found`.
- [ ] Record the date the live job last verified each site, and show it in `footprint sites`.

## Any time after v0.1

Scan controls and privacy:

- [ ] Add a `--redact` flag that masks the email in `--json` and `--md` output for sharing.
- [ ] Write report files with 0600 permissions.
- [ ] Read API keys such as `HIBP_API_KEY` from a config file or the OS keychain, in addition to environment variables.
- [x] Add a `--proxy` flag for SOCKS5 and HTTP proxies. Requests still go only to the site being checked. (also socks5h for Tor)

Coverage without new site checks:

- [ ] Check the email's domain locally: MX records, SPF and DMARC policy, and whether it is a disposable-email provider. These are DNS lookups only, and the email itself is never sent.
- [x] Accept many subjects in one run via `--batch <file>`, scanned together. (per-subject reports; JSON is an array)
- [x] Mark profile hits that came from the mailbox name in an email scan, since they are weaker evidence than an email match.

## Investigative suite (built on the `investigative-suite` branch)

Landed, each with tests:

- [x] Passive by default. `--allow-notify` gates password-reset checks (`checker.Notifies`).
- [x] Confidence per finding: `high`/`medium`/`low` on every found row (`checker.Confidence`, in JSON and the Markdown findings table).
- [x] Breach timeline. `checker.BreachHit{Name,Date}` on results; leakcheck captures dates; the case note lists breaches oldest first. No stolen values.
- [x] `--proxy` for http/https/socks5/socks5h (Tor via `socks5h://127.0.0.1:9050`); a bad proxy is a hard error.
- [x] Purpose logging. `--case-id` and `--authority` required with `--save`; operator captured from the environment.
- [x] Evidence integrity. Signed (Ed25519), hash-chained, append-only audit ledger per case directory; `footprint verify` re-checks files, chain, and signatures.
- [x] `--batch <file>` scans many subjects in one run.
- [x] `footprint export` builds a pivot graph (`pkg/graph`) and writes GraphML, Neo4j JSON, STIX 2.1, MISP, and Maltego CSV.

Follow-ups worth doing next:

- [ ] Capture a per-result SHA-256 of the raw HTTP response at the `httpx` layer (the hash reveals nothing, but plumbing it to `Result` without retaining bodies needs care; keeps the no-stolen-values boundary).
- [ ] A real Maltego transform server (local HTTP), beyond the import CSV.
- [x] Audit key kept off the case directory (`FOOTPRINT_SIGN_KEY` or the user config dir, `footprint keygen`); `verify` trusts only `--pubkey` / the local public key, never the key inside the ledger; `--head` catches a truncated ledger.
- [ ] Keep the audit signing key in the OS keychain or a hardware token instead of a file.
- [ ] Wire `--proxy`, `--case-id`, and `--authority` into the `lookup` network calls' own client, and into the future MCP server.
- [ ] CI: `go test -race`, `go vet`, `govulncheck`, and `gofmt` gate; GoReleaser with SBOM + cosign.
