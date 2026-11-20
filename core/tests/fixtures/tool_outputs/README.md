# Recorded tool outputs

Fixtures here stand in for real tool output so adapters can be unit-tested when a tool is not installed.

**Provenance (be honest about it):** these files are *hand-written to the documented report schema* of each
tool, not recordings of a real run. Every adapter test that uses them is "pending real-tool verification".
When the tools are installed, re-run the adapters on the real binaries (branch `chore/verify-tools`) and replace
these with genuine recordings. They contain no real secret: values are `REDACTED` and the tests build any
secret-shaped text at run time.

| File | Tool / schema | Used by |
|---|---|---|
| `gitleaks_report_sample.json` | Gitleaks >= 8.19 `--report-format json` (Betterleaks is a drop-in) | `test_layer1_secrets.py` |
| `semgrep_sample.json` | Semgrep `--json` schema (hand-written; Semgrep could not be installed on this Windows/Python 3.15 box) | `test_layer2_sast.py` |
| `bandit_corpus.json` | **Real** `bandit -r demo-apps/flask-corpus -f json` output (Bandit 1.9.4). Edited only to drop the `code` field and mask one generated key in `issue_text`; the project path is `{{PROJECT}}` | `test_layer2_sast.py` |
