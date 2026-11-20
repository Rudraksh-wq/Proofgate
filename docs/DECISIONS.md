# Design decisions

One line per change to the plan's design, with the reason. Newest last.

| Date | Decision | Why |
|---|---|---|
| 2026-11-20 | Docker is never required. It stays an optional backend, used only where it already exists (for example GitHub Actions runners). | The development machine is a Windows laptop without Docker; a hard Docker dependency made branches 15, 16 and the live checks impossible to run. |
| 2026-11-20 | Layer 9 scans only `.next/static`, `dist/` and `build/`, and only when they already exist (a missing build is a note under `--full`). | `.next/server` is server-side code that may legitimately hold server env values; and a scan must never run a build. |
| 2026-11-20 | Layer 9 reuses Layer 1's patterns and fingerprints and tags its hits `proofgate-bundle`. | The same secret found by both layers then merges into one finding with `confirmed_by = 2` instead of two alerts. |
| 2026-11-20 | Layer 6 decides "committed `.env`" with `git check-ignore` inside a repository and the project's `.gitignore` otherwise. | A `.env` that is git-ignored is the correct setup and must not be flagged; a fixture outside a repository still needs an answer. |
| 2026-11-20 | Checkov findings are `medium` confidence and only from the SARIF it writes to a temporary directory. | Checkov is not installed on the laptop, so the adapter is verified against a hand-written sample only: pending real-tool verification. |
