import { readFileSync } from "node:fs";
import path from "node:path";

// The benchmark page shows ONLY what bench/results.json says, read at build time. Nothing is typed in here.
export type Score = {
  available: boolean;
  reason?: string;
  overall?: { precision: number | null; recall: number | null; f1: number | null; items_found: number; items_missed: number; matching_findings: number; false_positives: number };
  by_category?: Record<string, { precision: number | null; recall: number | null; f1: number | null; items: number }>;
  misses?: string[];
  false_positives?: string[];
  of?: string[];
};

export type Results = {
  generated_at: string;
  proofgate_version: string;
  environment: { python: string; platform: string; network: boolean; subset: string[] | null; tolerance_lines: number; bench_seconds: number };
  corpus: { apps: number; ground_truth_items: number; clean_apps: number };
  tables: Record<string, Score>;
  heldout: { apps: number; note?: string };
  counts: Record<string, { raw: number; unique: number; proven: number; seconds_median_per_app: number }>;
  proof_rate: { recall: number | null; proven_precision: number | null; proven_findings: number };
  fix_verification: { cases: number; rescan_accuracy: number; tournament_accuracy: number; tournament_correct: string; details: { fix: string; kind: string; should_accept: boolean; rescan_says_clean: boolean; tournament_accepts: boolean }[] };
  latency: { inline_check_median_ms_per_file: number; hook_pre_median_ms: number; hook_fail_open_count: number; runs_per_file: number };
  targets: Record<string, { measured: number; target: number; met: boolean } | Record<string, unknown>>;
  notes: string[];
};

export function loadResults(): Results {
  const file = path.join(process.cwd(), "..", "bench", "results.json");
  return JSON.parse(readFileSync(file, "utf8")) as Results;
}

export const COLUMN_LABELS: Record<string, string> = {
  bandit: "Bandit",
  pip_audit: "pip-audit",
  semgrep: "Semgrep",
  betterleaks: "Betterleaks",
  osv_scanner: "OSV-Scanner",
  splinter: "Splinter",
  union: "Union of the tools above (what exists today)",
  proofgate_fast: "ProofGate fast",
  proofgate_full: "ProofGate full (with layer 7 dast-lite)",
  proofgate_full_no_dast: "ProofGate full without layer 7",
};

export const pct = (x: number | null | undefined) => (x === null || x === undefined ? "n/a" : x.toFixed(2));
