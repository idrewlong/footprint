# Improvements

Ideas for footprint beyond the roadmap in `project-overview.md`. Every item stays within the boundaries in `AGENTS.md`: checks run locally, nothing logs in, no stolen values are returned, and an unknown outcome is never `not_found`.

Items are grouped by the milestone they fit best. The last section holds items that can land any time after v0.1.

## Now: finish v0.1

- [ ] Make a first commit so CI and GoReleaser have history to work from.
- [ ] Update `project-overview.md` to cover `pkg/profiles`, the `footprint user` command, and the `breach` method.
- [ ] List all four methods (`register`, `login`, `password_reset`, `breach`) in the comment on `Result.Method`.
- [ ] Resolve the policy conflict. Step 5 of the overview's "Contributing a site" rejects checks that notify the account owner. `AGENTS.md` allows password-reset checks that email the address. Pick one rule and update both files.
- [x] Add an `Evidence` field to `Result` that records the signal a check relied on, such as "signup endpoint said 'email already in use'". Fill it in for every existing site and fixture test.
- [ ] Add a `--quiet` flag that skips checks that email the target, which are the `password_reset` methods.

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
- [ ] Add a `--proxy` flag for SOCKS5 and HTTP proxies. Requests still go only to the site being checked.

Coverage without new site checks:

- [ ] Check the email's domain locally: MX records, SPF and DMARC policy, and whether it is a disposable-email provider. These are DNS lookups only, and the email itself is never sent.
- [ ] Accept several addresses in one run (`--email a@x --email b@y`) and merge them into one report.
- [x] Mark profile hits that came from the mailbox name in an email scan, since they are weaker evidence than an email match.
