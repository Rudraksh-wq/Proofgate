import { BLIND_SPOTS, LIMITS_STATEMENT } from "@/lib/site";

export const metadata = { title: "What ProofGate cannot prove" };

export default function Limits() {
  return (
    <>
      <h1>What ProofGate cannot prove</h1>
      <div className="limits"><b>The honest boundary.</b> {LIMITS_STATEMENT}</div>
      <p>ProofGate never says an app is secure, and no report it writes will. A report ends with the sentence above. These are the limits behind it.</p>

      <h2>Known blind spots</h2>
      <p>Printed in every report:</p>
      <ul>{BLIND_SPOTS.map((b) => <li key={b}>{b}</li>)}</ul>

      <h2>What can be known where</h2>
      <div className="scroll">
        <table>
          <thead><tr><th>Question</th><th>Static checks</th><th>Needs the contract</th><th>Needs the running app</th></tr></thead>
          <tbody>
            <tr><td>Is RLS on? Does a policy exist?</td><td>yes</td><td></td><td></td></tr>
            <tr><td>Is <code>using(true)</code> on SELECT a bug?</td><td>no</td><td>yes</td><td>confirms</td></tr>
            <tr><td>Does the policy compare the right column to <code>auth.uid()</code>?</td><td>heuristic</td><td>yes</td><td>yes</td></tr>
            <tr><td>Does a route use the service_role key (which skips RLS)?</td><td>yes</td><td></td><td></td></tr>
            <tr><td>&hellip;and does it check ownership?</td><td>heuristic</td><td>yes</td><td>yes</td></tr>
            <tr><td>Is auth only in <code>middleware.ts</code>?</td><td>yes</td><td></td><td>best effort</td></tr>
          </tbody>
        </table>
      </div>

      <h2>Other limits</h2>
      <ul>
        <li><b>&ldquo;Proven&rdquo; means proven against your contract.</b> A canary crossing a boundary is strong evidence, but a wrong contract or a wrong seed can still mislead. Results against an unconfirmed contract are labelled as a draft.</li>
        <li><b>Untested is not safe.</b> A table that could not be seeded, or a route that could not be reached, is listed as untested.</li>
        <li><b>Layer 7 is a passive check, and without ZAP it is a basic one.</b> With ZAP installed ProofGate runs a passive ZAP scan of the running app on localhost (not yet verified against a real install). Without it, it runs <code>dast-lite</code>: security headers, cookie flags, CORS, exposed source maps and directory listings. <code>dast-lite</code> is not equal to ZAP, and its findings are labelled so. Layer 7 never scans anything but localhost.</li>
        <li><b>The live Supabase checks need a test project.</b> Without one, ProofGate checks your migrations statically and says so. No Docker is required.</li>
        <li><b>Hosted mode sends test traffic to your own Supabase project.</b> It signs up throwaway users, plants canary rows, attacks the project as a second user and deletes them again. <b>No source code is sent.</b> It only runs against a project whose ref you put on an allow-list, and only when you confirm with <code>--i-own-this</code>; each hosted run is logged in the report.</li>
        <li><b>The benchmark is small and synthetic.</b> See <a href="/benchmark/">the benchmark page</a> for exactly what was measured and what was not.</li>
      </ul>
    </>
  );
}
