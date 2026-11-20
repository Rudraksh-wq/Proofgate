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

| Supabase probe (layer 8) over HTTP on a hosted project | `proofgate prove demo-apps/nextjs-supabase --backend hosted --i-own-this` on each variant | A: anon and B read, list, change and delete A's row (5 proven). B: the same except anon (4 proven). C: held, owner oracles pass. Cleanup verified: no probe user left. |
| Next.js route replay (`next dev` on a random port, pointed at the hosted project) | same command, variant C | RLS holds, but the planted service-role route is PROVEN: `GET /api/notes/[id]` (read), `PUT /api/notes/[id]` (write) and the SQL injection in `GET /api/search`. |
| Live fix tournament, Tier B, on the hosted project | `proofgate fix ... --finding <id> --backend hosted --i-own-this --variant A` | RLS migration (14 lines) for the PostgREST finding: ACCEPTED, all gates pass, A becomes C. ssr-client switch (12 lines) for the route finding: ACCEPTED. The database is restored to the original state after each candidate. |

## Found by running against the real thing

- A pasted database URL whose password contains `@` is parsed by libpq at the first `@`, so the connection failed with a host-name error. `.env` values are now percent-encoded before use.
- `splinter.sql` is several statements (`SET`, a `DO` block, then the query). The rows are in the last result set, not the first.
- **The probe's own cleanup deadlocked the Auth server.** A default psycopg connection keeps its first statement's transaction open, so `conn.transaction()` was only a SAVEPOINT and the row delete was never committed; the Auth server's cascading `delete user` then waited on that lock and failed. The probe's connection is now autocommit.
- **A link to `node_modules` breaks webpack** ("Can't resolve ./D:/...") and a copy is far too large. A live Next.js fix is evaluated in a copy inside `<project>/.proofgate/tmp/`, so Node finds the real packages by walking up.
- **PostgREST caches the schema.** After the replay the schema is reloaded (`notify pgrst, 'reload schema'`) before anything attacks it.
- Checkov's output file name (above), and Checkov's Windows launcher is a `.cmd` wrapper the hash-pinning runner cannot run, so on Windows it is skipped and recorded.

## Still pending real-tool verification

| Item | Why | Where it gets verified |
|---|---|---|
| Semgrep and our 21 rules (`semgrep --test`) | Semgrep does not install on Windows / Python 3.15 | `live-stack.yml` job `semgrep-rules` (Actions, Linux) |
| Native ZAP (`zap.bat`) | not installed | nothing yet; Docker ZAP and `dast-lite` are the fallbacks |
| Docker ZAP baseline | Docker is not used on this machine | `live-stack.yml` job `zap-baseline` |
| Local `supabase start` (`--backend local`) | needs Docker | `live-stack.yml` job `supabase-live` |
| Betterleaks / Gitleaks, OSV-Scanner, GuardDog | not installed (a download of unverified binaries was not approved) | install them yourself, then `proofgate doctor --pin <tool>` and re-run the adapter tests |
| Live fix verification on a `local` (Docker) backend | needs Docker | `live-stack.yml` (no fix step yet) |
| Gemini (contract, Tier C, explanations) | no paid-tier key used yet | not scheduled |

## Tool versions and hashes seen (not committed to the lock)

`tools.lock.json` ships with no hashes on purpose (a test enforces it): a SHA-256 of a virtual-environment launcher differs per machine, and a lock
nobody generated would be an invented one. Run `proofgate doctor --pin <tool>` after installing a tool yourself. What was observed on the
verification machine (Windows 11, `win32-AMD64`):

| Tool | Version | SHA-256 of the executable |
|---|---|---|
| pip-audit | 2.10.1 | `7b7586467cae4b5efbbb6453a2c73d802032d36ca799087c114e4455a1940ca9` |
| bandit | 1.9.4 | `a904a413728eb2ffb5bf41202337bfcd42b0146e94e820b33442f1c7dc84a18a` |
| checkov | 3.4.6 | not pinned: the Windows launcher is a `.cmd` wrapper |
