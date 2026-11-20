"""Local report.html (plan 6.1, 6.5): one self-contained file you open from disk.

No JavaScript, no external fonts/images/requests, nothing leaves the machine. Every string is redacted and
HTML-escaped before it is written.
"""
from __future__ import annotations

from html import escape

from .models import FixResult, Finding, Report
from .redact import redact

BLIND_SPOTS = [
    "multi-step flows", "routes that need complex request bodies", "lookups by something other than an id (for example ?email=)",
    "storage buckets", "edge functions", "business logic", "payments",
]

_CSS = """
:root{--bg:#fff;--fg:#14171c;--muted:#5a6472;--line:#dfe3e8;--card:#f6f8fa;--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#2563eb;--ok:#15803d;--bad:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e8ecf1;--muted:#9aa5b3;--line:#273039;--card:#161c23;--crit:#ff8a80;--high:#ffab70;--med:#f2c55c;--low:#8ab4ff;--ok:#6fd08c;--bad:#ff8a80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px 64px}h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.15rem;margin:32px 0 12px}
.muted{color:var(--muted)}.counts{display:flex;gap:12px;flex-wrap:wrap;align-items:baseline;margin:16px 0}
.counts b{font-size:2rem}.counts span{color:var(--muted)}.arrow{color:var(--muted);font-size:1.4rem}
.limits{border:1px solid var(--line);border-left:4px solid var(--med);background:var(--card);padding:12px 14px;border-radius:6px;margin:16px 0}
.card{border:1px solid var(--line);background:var(--card);border-radius:8px;padding:14px 16px;margin:12px 0}
.badge{display:inline-block;font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;border:1px solid currentColor;margin-right:8px}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}
.proven{color:var(--ok);border-color:var(--ok)}code,pre{font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.tick{color:var(--ok)}.cross{color:var(--bad)}dl{margin:8px 0 0;display:grid;grid-template-columns:max-content 1fr;gap:2px 12px}dt{color:var(--muted)}dd{margin:0}
""".strip()


def _e(text: object) -> str:
    return escape(redact(str(text)), quote=True)


def _finding_card(f: Finding) -> str:
    badges = f'<span class="badge {f.severity}">{_e(f.severity)}</span>'
    if f.proven:
        badges += '<span class="badge proven">proven</span>'
    elif f.confirmed_by >= 2:
        badges += f'<span class="badge">{f.confirmed_by} tools agree</span>'
    loc = f.location
    where = f"{_e(loc.file)}:{loc.line}" + (f" &middot; {_e(loc.function)}" if loc.function else "") + (
        f" &middot; {_e(loc.route)}" if loc.route else "")
    rows = [("Where", f"<code>{where}</code>"), ("Rule", f"<code>{_e(f.rule)}</code>" + (f" &middot; {_e(f.cwe)}" if f.cwe else "")),
            ("Found by", _e(", ".join(f.sources))), ("Layer", str(f.layer)), ("Status", _e(f.status))]
    if f.fixed_in:
        rows.append(("Fixed in", _e(f.fixed_in)))
    if f.contract_rule:
        draft = "" if f.contract_confirmed else " (against the draft contract)"
        rows.append(("Broken rule", _e(f.contract_rule) + draft))
    if f.fix_tier:
        rows.append(("Fix tier", _e(f.fix_tier)))
    evidence = ""
    if f.evidence:
        ev = f.evidence
        who = f" ({_e(ev.actor)} &rarr; {_e(ev.victim)})" if ev.actor and ev.victim else ""
        evidence = (f"<p><b>Evidence</b>{who}</p><pre>{_e(ev.request)}\nHTTP {ev.status}\n{_e(ev.response_excerpt)}</pre>")
    dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
    return (f'<article class="card" id="{_e(f.id)}"><div>{badges}<b>{_e(f.title.split(" (")[0])}</b></div>'
            f'<p>{_e(f.plain_words)}</p>{evidence}<dl>{dl}</dl></article>')


def _gate(label: str, ok: bool | None) -> str:
    if ok is None:
        return f'<li class="muted">&ndash; {label} (n/a)</li>'
    return f'<li class="{"tick" if ok else "cross"}">{"&#10003;" if ok else "&#10007;"} {label}</li>'


def _fix_card(fx: FixResult) -> str:
    g = fx.gates
    gates = "".join([
        _gate("same exploit now fails", g.exploit_blocked), _gate("owner's feature still works", g.feature_works),
        _gate("existing tests pass", g.tests_pass), _gate("no new findings", g.no_new_findings),
        _gate("small, local diff", g.diff_is_small), _gate("migrations replayed from scratch", g.migrations_replayed)])
    verdict = "accepted" if fx.accepted else "not accepted"
    patch = f"<pre>{_e(fx.winner.patch)}</pre>" if fx.winner else ""
    rejected = "".join(f"<li>{_e(r.reason)}</li>" for r in fx.rejected)
    extra = (f"<p>Regression test: <code>{_e(fx.regression_test)}</code></p>" if fx.regression_test else "") + (
        f"<p>Rule for future AI sessions: {_e(fx.learned_rule)}</p>" if fx.learned_rule else "")
    return (f'<article class="card"><div><span class="badge {"proven" if fx.accepted else "high"}">{verdict}</span>'
            f"<b>Fix for {_e(fx.finding_id)}</b> (tier {_e(fx.tier)}, {fx.candidates} candidate(s))</div>"
            f'<ul style="list-style:none;padding-left:0">{gates}</ul>{patch}'
            + (f"<p>Rejected candidates:</p><ul>{rejected}</ul>" if rejected else "") + extra + "</article>")


def to_html(report: Report) -> str:
    r = report.receipt
    receipt = f"{r.rules_attacked} rules attacked, {r.rules_held} held" + (f", commit {_e(r.commit)}" if r.commit else "")
    findings = "".join(_finding_card(f) for f in report.findings) or '<p class="muted">No findings from the layers that ran.</p>'
    fixes = "".join(_fix_card(fx) for fx in report.fixes)
    tools = "".join(
        f"<tr><td>{_e(t.name)}</td><td>{_e(t.status)}</td><td>{_e(t.version or '-')}</td>"
        f"<td><code>{_e((t.sha256 or '-')[:12])}</code></td></tr>" for t in report.tools)
    notes = "".join(f"<li>{_e(n)}</li>" for n in report.notes)
    tested = ", ".join(_e(x) for x in [*report.tested.tables, *report.tested.routes]) or "nothing yet"
    untested = "".join(f"<li>{_e(u)}</li>" for u in report.untested)
    blind = "".join(f"<li>{_e(b)}</li>" for b in BLIND_SPOTS)
    sections = [
        f"<h1>ProofGate report: {_e(report.project)}</h1>",
        f'<div class="muted">{_e(report.scanned_at)} &middot; layers run: {_e(", ".join(map(str, report.layers_run)) or "none")}</div>',
        f'<div class="counts"><div><b>{report.raw_warning_count}</b> <span>raw</span></div><span class="arrow">&rarr;</span>'
        f'<div><b>{report.unique_count}</b> <span>unique</span></div><span class="arrow">&rarr;</span>'
        f'<div><b>{report.proven_count}</b> <span>proven</span></div></div>',
        f'<div class="limits"><b>What this report does not mean.</b> {_e(report.limits_statement or "")}</div>',
        f'<p class="muted">{receipt}</p>',
        "<h2>Findings</h2>" + findings,
    ]
    if report.accepted_risks:
        rows = "".join(
            f"<tr><td>{_e(x.title)}</td><td>{_e(x.severity)}{', proven' if x.proven else ''}</td><td>{_e(x.owner)}</td>"
            f"<td>{_e(x.expires.isoformat())}</td><td>{'FORCED' if x.forced else ''}</td><td>{_e(x.reason)}</td></tr>" for x in report.accepted_risks)
        sections.append('<h2>Accepted risks</h2><p class="muted">A person accepted these; they do not count toward the exit code. '
                        'They are listed so the decision stays visible.</p><table><tr><th>Finding</th><th>Severity</th><th>Owner</th>'
                        '<th>Expires</th><th></th><th>Reason</th></tr>' + rows + "</table>")
    if fixes:
        sections.append("<h2>Fixes</h2>" + fixes)
    if notes:
        sections.append(f"<h2>Notes</h2><ul>{notes}</ul>")
    sections.append("<h2>Tools</h2><table><tr><th>Tool</th><th>Status</th><th>Version</th><th>SHA-256</th></tr>" + tools + "</table>")
    sections.append(f"<h2>What was tested</h2><p>{tested}</p>" + (f"<h3>Untested</h3><ul>{untested}</ul>" if untested else ""))
    sections.append(f"<h2>Known blind spots</h2><ul>{blind}</ul>")
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>ProofGate report: {_e(report.project)}</title><style>{_CSS}</style></head>"
            f"<body><main>{''.join(sections)}</main></body></html>")
