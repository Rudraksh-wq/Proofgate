import { COLUMN_LABELS, loadResults, pct } from "@/lib/bench";

export const metadata = { title: "ProofGate benchmark (measured)" };

export default function Benchmark() {
  const r = loadResults();
  const cols = Object.entries(r.tables);
  const fv = r.fix_verification;
  return (
    <>
      <h1>Benchmark</h1>
      <p className="lede">
        Every number on this page is read from <code>bench/results.json</code>, measured on one machine on {r.generated_at.slice(0, 10)}. Nothing is typed in by hand,
        and a tool that was not installed has no number.
      </p>
      <div className="limits">
        <b>Read this first.</b> The corpus is {r.corpus.apps} small synthetic Flask apps ({r.corpus.ground_truth_items} planted flaws, {r.corpus.clean_apps} clean apps). It shows how
        ProofGate does on this corpus, not on real apps. The apps and ProofGate&apos;s rules were written by the same team. {r.heldout.apps === 0 ? "The sealed held-out set (apps written and labelled by someone outside the team) has not been provided, so there is no held-out number." : ""}
      </div>

      <h2>Precision, recall and F1</h2>
      <p className="muted">A planted flaw is found when a tool reports the same category in the same file within {r.environment.tolerance_lines} lines. A finding that matches nothing is a false positive.</p>
      <div className="scroll">
        <table>
          <thead>
            <tr><th>Column</th><th className="num">Precision</th><th className="num">Recall</th><th className="num">F1</th><th className="num">Access recall</th></tr>
          </thead>
          <tbody>
            {cols.map(([name, t]) => (
              <tr key={name}>
                <td>{COLUMN_LABELS[name] ?? name}</td>
                {t.available && t.overall && t.by_category ? (
                  <>
                    <td className="num">{pct(t.overall.precision)}</td>
                    <td className="num">{pct(t.overall.recall)}</td>
                    <td className="num">{pct(t.overall.f1)}</td>
                    <td className="num">{pct(t.by_category.access.recall)}</td>
                  </>
                ) : (
                  <td colSpan={4} className="muted">not measured: {t.reason}</td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted">&ldquo;ProofGate fast&rdquo; does not attack the app, so its access recall is 0 by design. &ldquo;ProofGate full&rdquo; adds the second-user probe.</p>

      <h2>Raw, unique, proven</h2>
      <div className="scroll">
        <table>
          <thead><tr><th>Tier</th><th className="num">Raw</th><th className="num">Unique</th><th className="num">Proven</th><th className="num">Median seconds per app</th></tr></thead>
          <tbody>
            {Object.entries(r.counts).map(([name, c]) => (
              <tr key={name}><td>{COLUMN_LABELS[name] ?? name}</td><td className="num">{c.raw}</td><td className="num">{c.unique}</td><td className="num">{c.proven}</td><td className="num">{c.seconds_median_per_app}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
      <p>Of the access and injection flaws, ProofGate proved {pct(r.proof_rate.recall)} of them, with proven-finding precision {pct(r.proof_rate.proven_precision)} ({r.proof_rate.proven_findings} proven findings).</p>

      <h2>Judging fixes</h2>
      <p>
        On {fv.cases} candidate fixes (a correct, a lazy and a partial fix for four bugs), a gate that only asks &ldquo;does a re-scan say clean?&rdquo; decided correctly {pct(fv.rescan_accuracy)} of the time.
        The tournament decided correctly {pct(fv.tournament_accuracy)} of the time ({fv.tournament_correct}).
      </p>
      <div className="scroll">
        <table>
          <thead><tr><th>Fix</th><th>Should accept</th><th>Re-scan says clean</th><th>Tournament accepts</th></tr></thead>
          <tbody>
            {fv.details.map((d) => (
              <tr key={d.fix}>
                <td>{d.fix}</td><td>{String(d.should_accept)}</td>
                <td>{String(d.rescan_says_clean)} <span className={`pill ${d.rescan_says_clean === d.should_accept ? "ok" : "bad"}`}>{d.rescan_says_clean === d.should_accept ? "right" : "wrong"}</span></td>
                <td>{String(d.tournament_accepts)} <span className={`pill ${d.tournament_accepts === d.should_accept ? "ok" : "bad"}`}>{d.tournament_accepts === d.should_accept ? "right" : "wrong"}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>Speed</h2>
      <p>
        The inline check takes a median of {r.latency.inline_check_median_ms_per_file} ms per file; the whole hook (including starting the check) a median of {r.latency.hook_pre_median_ms} ms
        (median of {r.latency.runs_per_file} runs). Hook fail-opens during the run: {r.latency.hook_fail_open_count}.
      </p>

      <h2>Every miss and every false positive</h2>
      {["proofgate_full", "union"].map((name) => {
        const t = r.tables[name];
        if (!t?.available) return null;
        return (
          <details key={name}>
            <summary>{COLUMN_LABELS[name]}: {t.misses?.length ?? 0} missed, {t.false_positives?.length ?? 0} false positives</summary>
            <ul>
              {(t.misses ?? []).map((m) => <li key={m}>missed: {m}</li>)}
              {(t.false_positives ?? []).map((m) => <li key={m}>false positive: {m}</li>)}
            </ul>
          </details>
        );
      })}

      <h2>Method and honesty</h2>
      <ul>{r.notes.map((n) => <li key={n}>{n}</li>)}</ul>
      <p className="muted">
        Run on Python {r.environment.python}, {r.environment.platform}, ProofGate {r.proofgate_version}, network {r.environment.network ? "on" : "off"}. Re-run it yourself:{" "}
        <code>python bench/run_bench.py</code>.
      </p>
    </>
  );
}
