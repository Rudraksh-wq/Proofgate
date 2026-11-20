import { LAYERS } from "@/lib/site";

export const metadata = { title: "How ProofGate works" };

export default function HowItWorks() {
  return (
    <>
      <h1>How it works</h1>
      <p className="lede">Contract, hook, nine layers, the second user, the tournament, and a lesson that sticks.</p>

      <ol className="steps">
        <li>
          <b>The contract.</b> ProofGate writes down who may do what (&ldquo;User B must never read or change User A&apos;s notes&rdquo;), from your README and your
          table and route names. A column heuristic runs first and wins ties; an optional language model may only <i>propose</i> additions. Anything that would
          make data more public is held for you to confirm. Until you confirm it, results are labelled &ldquo;against draft contract&rdquo;.
        </li>
        <li>
          <b>The hook.</b> Before your AI writes a file, the inline checks (secrets, risky code, package names) run in a few milliseconds. A live key or a package
          that does not exist is blocked, with the reason and the exact fix. Anything else is allowed. If the check ever crashes or is slow, it lets the write through and counts it, so it can never lock you out.
        </li>
        <li>
          <b>Nine layers.</b>
          <ul>
            {LAYERS.map((l) => (
              <li key={l.n}>{l.n}. {l.name}: {l.what} ({l.tool})</li>
            ))}
          </ul>
        </li>
        <li>
          <b>The second user.</b> The probe starts your app on a random local port with a throwaway database, signs up User A, User B, an admin and an anonymous visitor,
          has A create rows containing random canary strings, and then attacks as the others: read A&apos;s item, list with A&apos;s id, open admin routes, inject SQL and shell
          commands, write to A&apos;s row, and escalate a normal user to admin. If a canary or another user&apos;s e-mail crosses a boundary, that is <b>proven</b>, with the
          request and a masked excerpt. What it could not set up is reported as <b>untested</b>, never as safe.
        </li>
        <li>
          <b>The tournament.</b> A fix, whoever wrote it (a template, an AI, a person), is applied in a temporary copy and must pass five gates: the same attack now fails;
          every owner action that worked before still works; your tests pass; the fast checks find nothing new; the diff is small and stays in the finding&apos;s file.
          For Supabase, all migrations are replayed from scratch and an edit to an old migration is rejected.
        </li>
        <li>
          <b>Vaccinate.</b> The exploit becomes a regression test that fails on the original and passes on the fix, and the lesson is written into a marked block in
          <code> CLAUDE.md</code>, <code>AGENTS.md</code> and <code>.cursor/rules/proofgate.mdc</code>, visible in your diff.
        </li>
      </ol>

      <h2>What stays on your machine</h2>
      <p>Your code, your database, your keys and the throwaway users all stay local. ProofGate reads keys from environment variables only and redacts every log line, hook message, tool reply and model prompt.</p>

      <h2>What may be sent to Gemini</h2>
      <p>Nothing, unless you opt in with a paid-tier key (the free tier may use prompts to improve Google&apos;s products) and do not set <code>PROOFGATE_OFFLINE=1</code>. Then:</p>
      <ul>
        <li><b>Contract drafting:</b> your README prose, route names and table and column names, redacted.</li>
        <li><b>Tier C fixes:</b> one redacted function of at most 60 lines, and a description of the problem. Never <code>.env</code>, never database rows, never the whole repository.</li>
        <li><b>Explanations:</b> the finding&apos;s text, redacted.</li>
      </ul>
      <p>Every answer is validated against a schema; a patch is a diff that must pass the tournament; a rule that makes data public needs your confirmation. Text found in your repository is treated as data, never as instructions, and a comment such as <code>// proofgate-ignore</code> does nothing.</p>

      <h2>This website</h2>
      <p>It is static. It has no backend, no forms that take code, no accounts, no uploads and no analytics.</p>
    </>
  );
}
