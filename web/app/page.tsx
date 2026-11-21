import { LAYERS, LIMITS_STATEMENT, PITCH, STATS } from "@/lib/site";

export default function Home() {
  return (
    <>
      <h1>Proof, not alerts.</h1>
      <p className="lede">{PITCH}</p>
      <p>
        ProofGate is a security gate that lives inside the AI coding loop. It runs on your machine, checks what your AI writes, attacks your
        app as a second user on a throwaway local database, and accepts a fix only when the same attack fails and the owner&apos;s feature still works.
      </p>
      <div className="btns">
        <a className="btn primary" href="/install/#claude-code">Install for Claude Code</a>
        <a className="btn" href="/install/#mcp">MCP config</a>
        <a className="btn" href="/install/#cli">Command line</a>
      </div>
      <div className="limits"><b>Honest boundary.</b> {LIMITS_STATEMENT}</div>

      <h2>The problem</h2>
      <p>The worst leaks in AI-built apps are not bad code. They are missing access checks that nobody tested from another user&apos;s side.</p>
      {STATS.map((s) => (
        <blockquote key={s.source}>
          {s.text}
          <cite>{s.source}</cite>
        </blockquote>
      ))}

      <h2>What happens when you use it</h2>
      <ol className="steps">
        <li><b>It blocks a leaked key as it is written.</b> Your AI tries to put a live key in code. The write is stopped with the reason and the fix, the AI moves the key to an environment variable, and it tells you to rotate it.</li>
        <li><b>It shows the stolen data.</b> It signs up User B, reads User A&apos;s private note through your own routes, and shows you the masked row. Existing scanners said almost nothing about this.</li>
        <li><b>It only accepts a fix that provably works.</b> A fix that locks everyone out is rejected because the owner can no longer read their own note. A fix that still leaks is rejected because the attack still works. The correct fix is accepted, with a regression test and a rule for future AI sessions.</li>
      </ol>

      <h2>Nine layers</h2>
      <div className="grid">
        {LAYERS.map((l) => (
          <div className="card layer" key={l.n}>
            <b><span className="n">{l.n}</span>{l.name}</b>
            <span>{l.what}</span>
            <div className="tool">{l.tool}</div>
          </div>
        ))}
      </div>
      <p className="muted" style={{ marginTop: 12 }}>
        Layer 7 uses ZAP when installed and a basic built-in check (not equal to ZAP) otherwise. <a href="/benchmark/">The benchmark page</a> says exactly what has been measured.
      </p>

      <h2>Your code stays on your machine</h2>
      <p>
        Everything runs locally. The website you are reading does not scan, upload or store code, and has no backend. The only thing that can leave
        your machine. ProofGate runs locally and does not send project data to an external model.
        <a href="/how-it-works/"> How it works</a> lists exactly what is and is not sent.
      </p>
    </>
  );
}
