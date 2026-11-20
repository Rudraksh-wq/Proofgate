# What has been verified against the real thing

Last updated 2026-11-21 (branch `chore/verify-live-tools`). "Verified" means it ran against the real tool or service and the result was checked;
everything else is tested only against recorded or hand-written samples and is labelled pending.

## Verified

| Item | How | Result |
|---|---|---|
| Hosted Supabase test project, variants A / B / C | `scripts/reset_demo.py` then `scripts/ci_live_check.py` on a real project (a row planted by one user, read back as `anon` and as a different signed-in user) | A: anon and other user both see it. B: only the other signed-in user sees it. C: nobody. The database really changes with the variant. |
| Layer 5, live Splinter (pinned `splinter.sql`) | `proofgate scan --layers 5 --full --backend hosted --i-own-this` | A: `rls_disabled_in_public` flagged. B and C: not (Splinter does not judge policy logic). |
| Layer 5, contract-aware checks on the live catalogs | same run | A: `rls-disabled`. B: `policy-role-without-uid` (Splinter misses it). C: no policy finding. The planted `SECURITY DEFINER` function is flagged in all three. |
| Target guard | refused without the allow-list, refused without `--i-own-this`, allowed for the listed ref | covered by unit tests and the live runs above |
| Checkov adapter (layer 6) | real `checkov 3.4.6 -o sarif` run, recorded in `core/tests/fixtures/tool_outputs/checkov_sample.sarif` | found and fixed a real mismatch: Checkov writes `results_sarif.sarif`, not `results.sarif` |
| Bandit, pip-audit, npm audit adapters (layers 2, 3) | real runs (earlier branches) | recorded outputs are real |
| New Supabase key format | `sb_secret_` / `sb_publishable_` keys on the hosted project | detected, masked and sent as `apikey` only |

## Found by running against the real thing

- A pasted database URL whose password contains `@` is parsed by libpq at the first `@`, so the connection failed with a host-name error. `.env` values are now percent-encoded before use.
- `splinter.sql` is several statements (`SET`, a `DO` block, then the query). The rows are in the last result set, not the first.
- Checkov's output file name (above), and Checkov's Windows launcher is a `.cmd` wrapper the hash-pinning runner cannot run, so on Windows it is skipped and recorded.

## Still pending real-tool verification

| Item | Why | Where it gets verified |
|---|---|---|
| Semgrep and our 21 rules (`semgrep --test`) | Semgrep does not install on Windows / Python 3.15 | `live-stack.yml` job `semgrep-rules` (Actions, Linux) |
| Native ZAP (`zap.bat`) | not installed | nothing yet; Docker ZAP and `dast-lite` are the fallbacks |
| Docker ZAP baseline | Docker is not used on this machine | `live-stack.yml` job `zap-baseline` |
| Local `supabase start` (`--backend local`) | needs Docker | `live-stack.yml` job `supabase-live` |
| Betterleaks / Gitleaks, OSV-Scanner, GuardDog | not installed (a download of unverified binaries was not approved) | install them yourself, then `proofgate doctor --pin <tool>` and re-run the adapter tests |
| Gemini (contract, Tier C, explanations) | no paid-tier key used yet | not scheduled |
| Next.js / Supabase route probe (HTTP through PostgREST) | not built (`feat/15`) | `feat/15-probe-supabase-nextjs` |

## Tool versions and hashes seen (not committed to the lock)

`tools.lock.json` ships with no hashes on purpose (a test enforces it): a SHA-256 of a virtual-environment launcher differs per machine, and a lock
nobody generated would be an invented one. Run `proofgate doctor --pin <tool>` after installing a tool yourself. What was observed on the
verification machine (Windows 11, `win32-AMD64`):

| Tool | Version | SHA-256 of the executable |
|---|---|---|
| pip-audit | 2.10.1 | `7b7586467cae4b5efbbb6453a2c73d802032d36ca799087c114e4455a1940ca9` |
| bandit | 1.9.4 | `a904a413728eb2ffb5bf41202337bfcd42b0146e94e820b33442f1c7dc84a18a` |
| checkov | 3.4.6 | not pinned: the Windows launcher is a `.cmd` wrapper |
