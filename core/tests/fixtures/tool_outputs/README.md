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
| `pip_audit_requests_2_19_0.json` | **Real** `pip-audit 2.10.1 -r requirements.txt --no-deps --disable-pip -f json` for `requests==2.19.0` (advisory descriptions trimmed to 120 chars) | `test_layer3_deps.py` |
| `npm_audit_lodash.json` | **Real** `npm audit --json --package-lock-only` for `lodash@4.17.15` (npm 11) | `test_layer3_deps.py` |
| `osv_scanner_sample.json` | OSV-Scanner v2 `--format json` schema, hand-written (osv-scanner not installed): pending real-tool verification | `test_layer3_deps.py` |
| `guarddog_sample.json` | GuardDog `<eco> verify --output-format json`, hand-written, tolerant parser: pending real-tool verification | `test_layer4_packages.py` |
| `checkov_sample.sarif` | **Real** `checkov 3.4.6 -d . -o sarif` run on a Dockerfile and an S3 bucket Terraform file (recorded 2026-11-21; Checkov writes `results_sarif.sarif`) | `test_layer6_layer9.py` |
| `zap_report_sample.json` | ZAP `traditional-json` report (Automation Framework `report` job), hand-written (ZAP not installed): pending real-tool verification | `test_layer7_dast.py` |
