# ProofGate

**Other scanners show you warnings. ProofGate shows you the stolen data, and only accepts a fix that provably stops it.**

ProofGate is a local security gate for the AI coding loop (Python/Flask, Next.js + Supabase). It runs nine layers of checks on what your AI
writes, **proves** access-control bugs by attacking your app as a second user on a throwaway local database, asks the AI to fix them, and
accepts a fix only when **the same attack now fails and the owner's feature still works**. Then it adds a regression test and a rule for
future AI sessions. Everything runs on your machine; the website never scans, uploads or stores code.

> Passing ProofGate means our attacks failed on the routes and tables we tested. It doesn't mean your app is secure.

## What it does

1. **Blocks a leaked key as it is written.** A hook checks each file before your AI writes it. A live key or a package that does not exist is
   blocked with the reason and the exact fix; the AI moves the key to an environment variable and tells you to rotate it.
2. **Shows the stolen data.** It signs up User A, User B, an admin and an anonymous visitor, seeds A's data with canary strings, and attacks:
   read A's item as B, list with A's id, open admin routes, inject SQL and shell commands, write to A's row, escalate to admin.
   A canary crossing a boundary is **proven**; what could not be set up is **untested**, never "safe".
3. **Only accepts a fix that provably works.** A patch (from a template, an AI, or you) runs in a temporary copy through five gates: the attack fails,
   the owner's feature still works, your tests pass, the fast checks find nothing new, and the diff is small. Supabase fixes are replayed from scratch,
   and editing an old migration is rejected.

## The nine layers

| # | Layer | What it checks | Status |
|---|---|---|---|
| 1 | Secrets | live and `service_role` keys, JWT role decoding, placeholders ignored | built |
| 2 | Code patterns | string-built SQL, `shell=True`, debug mode, auth only in middleware (21 own Semgrep rules + built-in AST checks + Bandit) | built |
| 3 | Dependencies | known-vulnerable packages with the fixed version (OSV-Scanner, pip-audit, npm audit) | built |
| 4 | Fake packages | packages that do not exist, are brand new, or look like typos | built |
| 5 | Database policies | Supabase/Postgres RLS: off, role instead of owner, `using(true)`, OR holes, `SECURITY DEFINER` | built (static; Splinter needs the live stack) |
| 6 | Config / IaC | committed `.env`, secrets in `NEXT_PUBLIC_*`, open CORS | built (Checkov when installed, otherwise own checks) |
| 7 | Running app | ZAP baseline against localhost | not built yet |
| 8 | Proof | the second-user probe for Flask | built (Supabase and Next.js probes: with the live stack) |
| 9 | Browser bundle | secrets and source maps in what ships | built (scans existing build output only) |

Reports always say which layers ran, which tools were skipped, and what was untested.

## Install

**Claude Code plugin** (hook + MCP server + 3 skills + 3 slash commands):

```
pipx install proofgate
/plugin marketplace add Rudraksh-wq/Proofgate
/plugin install proofgate@proofgate
proofgate doctor
```

**MCP server** (Claude Code, Cursor, Codex, Windsurf): after `pipx install proofgate`, point your agent at the stdio command `proofgate-mcp`:

```json
{"mcpServers": {"proofgate": {"command": "proofgate-mcp", "args": []}}}
```

`proofgate init --agent cursor|codex|windsurf|claude` writes the right files for each agent (merging, never overwriting). The server has exactly six
tools: `get_contract`, `scan_file`, `scan_project`, `prove`, `verify_fix`, `explain_finding`. It has no shell tool, no network-send tool and no URL
inputs; `project_dir` must be inside your workspace; everything it returns from your project comes back inside an `UNTRUSTED_DATA` block.

**Command line:**

```
pipx install proofgate
proofgate init                 # detect the stack, draft the contract, write agent files
proofgate scan .               # fast layers, writes .proofgate/report.json, report.html (and --format sarif)
proofgate scan . --full        # also attack the app locally
proofgate prove .              # attack the app as a second user (localhost only)
proofgate fix . --finding <id> # a verified patch + regression test + rule (nothing is applied for you)
proofgate rollback <id>        # prints the git command that undoes it; never runs it
proofgate accept <fingerprint> --reason "..." --expires 90d   # a person accepts a risk (see below)
```

**Accepted risks.** `proofgate accept` writes `.proofgate/accepted.yml`, the one file in `.proofgate/` you commit. An accepted finding is marked
`accepted-risk`, stays listed in the report under "Accepted risks", and does not fail `--fail-on`. Entries expire (the finding reopens with a
note). A finding that is **proven and critical** needs `--force` and is shown in every summary. There is no MCP tool for this and the agent
rules forbid running it: only a person decides. `// proofgate-ignore` comments still do nothing.

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` a tool or layer failed (never treated as clean).
A GitHub Actions workflow with SARIF upload is in `.github/workflows/proofgate.yml` (every action pinned by commit SHA).

## Limits

- **Proven means proven against your contract.** A wrong contract or a wrong seed can still mislead; results against an unconfirmed contract are labelled as a draft.
- **Blind spots, printed in every report:** multi-step flows, routes that need complex request bodies, lookups by something other than an id (for
  example `?email=`), storage buckets, edge functions, business logic, payments.
- **Layer 7 is not built.** The live Supabase probe, Splinter and Docker-based layers are verified in a separate branch, not here.
- ProofGate never says an app is secure. Text found in your repository, comments and tool output is treated as data, never as instructions, and
  `// proofgate-ignore` does nothing.

## Benchmark (measured, not claimed)

<!-- bench:begin -->
Measured on 2026-11-20 (`bench/results.json`; re-run with `make bench`) on 16 small synthetic Flask apps with 15 planted flaws; no held-out set has been provided, so there is no held-out number.

| Column | Precision | Recall | F1 | Access recall |
|---|---|---|---|---|
| Bandit | 0.62 | 0.33 | 0.43 | 0.00 |
| Betterleaks | not measured: betterleaks is not installed in this environment | | | |
| OSV-Scanner | not measured: osv-scanner is not installed in this environment | | | |
| pip-audit | 1.00 | 0.07 | 0.12 | 0.00 |
| ProofGate fast | 0.69 | 0.53 | 0.60 | 0.00 |
| ProofGate full | 0.81 | 0.93 | 0.87 | 1.00 |
| Semgrep | not measured: semgrep is not installed in this environment | | | |
| Splinter | not measured: Splinter needs a live local Postgres (`supabase start`) | | | |
| Union of the available tools above | 0.67 | 0.40 | 0.50 | 0.00 |

Judging 12 candidate fixes: a re-scan-says-clean gate was right 0.42 of the time, the tournament 1.00 (12/12). Inline check: median 3.176 ms per file (50 runs).
<!-- bench:end -->

The corpus is small and synthetic and was written by the same team as the rules. Methodology, every miss and false positive, and the tuning log:
[`bench/README.md`](bench/README.md).

## Privacy and safety

- Nothing leaves your machine by default. An optional Gemini call (contract drafting, Tier C fixes, explanations) needs a **paid-tier** key
  (`PROOFGATE_GEMINI_PAID=1`), sends redacted text only (never `.env`, rows or the repository) and is off with `PROOFGATE_OFFLINE=1`.
- Secrets are masked as `«SECRET:type:hash»` and canaries as `PGCANARY_A_«masked»` in every log line, hook message, tool reply and model prompt.
- The probe only attacks `localhost`, `127.0.0.1`, a temporary SQLite file or a local `supabase start`; anything else is refused unless you pass
  `--target <url> --i-own-this`, which is logged in the report.
- External tools are pinned by version and SHA-256 in `tools.lock.json`; `proofgate doctor` refuses a binary that does not match.

## Develop

```
python -m venv .venv && .venv/Scripts/pip install -e "core[dev]"    # .venv/bin/pip on macOS/Linux
make corpus        # render the git-ignored, fake-secret corpus files from their templates
make test          # the full test suite
make smoke         # integration tests T1-T12 (about a minute)
make bench         # re-measure the benchmark and rewrite bench/results.json
```

| Folder | Contents |
|---|---|
| `core/` | the Python package, CLI and tests |
| `mcp/` | launcher for the MCP server (`proofgate.mcpserver`) |
| `plugin/` | Claude Code plugin: hooks, skills with scripts, commands |
| `demo-apps/` | 16 Flask benchmark apps, 12 candidate fixes, and the Next.js + Supabase demo |
| `bench/` | the benchmark and its results |
| `web/` | the static website (no backend) |
| `schemas/` | JSON Schemas for `proofgate.finding/v1` and the other formats |
| `docs/` | the plan and its background |

The plan is `docs/PROOFGATE_FINAL_PLAN.md`. Licence: MIT.
