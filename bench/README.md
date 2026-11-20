# ProofGate benchmark

One command re-runs everything and rewrites `bench/results.json`:

```
python bench/run_bench.py                  # full run (needs the network for pip-audit and the package registry)
python bench/run_bench.py --skip-network   # offline
make bench                                 # the same, from the repo root
```

Every number in `results.json` is **measured on the machine that ran it, at that moment**. Nothing is typed in by hand. A tool that is not
installed gets a column that says `available: false` and why; it never gets an estimated number.

## What is measured

| Section | Meaning |
|---|---|
| `tables.<column>` | precision, recall and F1, overall and per category (`access` is the headline), for: Bandit, pip-audit, Semgrep, Betterleaks, OSV-Scanner, Splinter, the **union** of the baseline tools that were available ("what exists today"), **ProofGate fast** and **ProofGate full** |
| `counts` | the three numbers per tier: raw -> unique -> proven |
| `proof_rate` | the share of access and injection items ProofGate *proved*, and the precision of its proven findings |
| `fix_verification` | on the 12 candidate fixes (correct, lazy, partial for v01, v05, v06, v07): accuracy of "a re-scan says clean" versus the tournament |
| `latency` | median inline check time per file and median hook time (50 runs each), and the hook fail-open count |
| `heldout` | the sealed held-out set, reported separately. **Empty until someone outside the team provides it** |
| `misses_and_false_positives` | one line for every miss and every false positive, per column |
| `targets` | the plan's targets next to the measured value, with `met` true/false |

**Matching rule.** A ground-truth item `{category, file, line}` is *found* when a tool reports a finding of the same category in the same
file within 12 lines. A finding that matches nothing is a false positive (every finding on a clean app is one). Precision counts findings;
recall counts ground-truth items (one finding can cover two neighbouring items).

## What this does and does not show

- The corpus is **16 small synthetic Flask apps**, one planted flaw each. It shows how ProofGate does on *this* corpus, not on real apps.
- The corpus and ProofGate's rules were written by the same team. The held-out set exists so that someone else's apps (labelled by
  manual two-user testing *before* running ProofGate) can answer "is the gain real or tuned to the corpus?". Until it exists, no held-out
  number exists, and `results.json` says so.
- Layers 6, 7 and 9 are not built yet, so `config` and `bundle` results mostly reflect the other layers.
- `fast` does not attack the app, so its access recall is 0 by design; `full` adds the Doppelganger probe.

## Honesty rules

1. Re-run from a clean clone before quoting a number.
2. Every false positive and false negative is listed with a one-line reason (`misses_and_false_positives`).
3. **Disclose any tuning done after seeing results** by adding a line to the log below. Rules were written before the first measurement.

### Tuning log

- 2026-11-20, before the first full measurement: the built-in Python-AST and JS checks (the same ones the inline hook runs) were added to
  layer 2, so that layer 2 does not depend on Semgrep being installed. This was a product change, made before any benchmark number existed.
