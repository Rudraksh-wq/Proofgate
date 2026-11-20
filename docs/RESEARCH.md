# RESEARCH.md: Making AI-written code safe to ship

**Research date:** 20 November 2026 (IST)
**Scope:** Web apps built with AI help, focused on TypeScript/Next.js + Supabase.
**Author's note on evidence:** Every claim below is labelled as one of:
- **[Verified]**: confirmed against a primary source (vendor docs, paper, advisory, original post).
- **[Vendor claim]**: published by a company about its own product or data. Treat it as marketing until someone reproduces it.
- **[Independent]**: published by a researcher or academic group that is not selling the thing being measured.
- **[Secondary]**: reported by press or a blog. The original was not checked.
- **[Inference]**: my own reasoning, not a sourced fact.
- **[Not tested]**: I did **not** install or run any tool in this research. All capability statements come from documentation, READMEs, advisories, and papers. Nothing here is a hands-on benchmark result.

**Limits of this research:** I used live web search and fetched pages (docs, READMEs, advisories, papers). I did not clone or execute third-party code, I did not scan any third-party app, and one GitHub directory listing (`supabase/splinter/lints`) was blocked by robots rules, so lint details for splinter come from Supabase docs and a third-party write-up. Pricing and free tiers change often. Re-check them before you rely on them.

---

## 0. Executive summary

1. **The commodity layers are already solved well and cheaply.** Secret scanning (Betterleaks/Gitleaks, TruffleHog, GitHub secret scanning), pattern-based SAST (Semgrep/Opengrep, CodeQL), and dependency scanning (OSV-Scanner, Dependabot) are mature. Some now run **inside AI agents**: Semgrep Guardian plugs into Claude Code/Cursor through hooks + MCP, and GitHub automatically runs CodeQL, secret scanning, and advisory checks on code from Copilot and third-party coding agents. **Building another one of these is wasteful.**
2. **The painful, unsolved gap is authorization: "can user A read or change user B's data?"** In Supabase apps, that is usually wrong RLS policies plus server code that uses the `service_role` key. Existing checks mostly confirm **that RLS exists**, not **that it is correct**. Supabase's own linter checks structure. The original Lovable researcher criticized Lovable's first scanner for checking only that a policy exists. Small open-source RLS test generators exist (rlsautotest, rlsgrid, supashield, rls-scope), but they are early, database-only, and not wired into the AI agent loop or the app's API routes.
3. **Recommended direction:** do not build "a 9-layer scanner." Build a narrow **proof-of-isolation gate** for Next.js + Supabase that the AI agent calls. It creates two or three test identities on a **local** Supabase stack, replays real data access through the app's actual API routes and the Supabase client, reports *proven* cross-user leaks with a reproducible test, and re-runs the same test to confirm the agent's fix. Reuse existing open-source scanners for secrets, dependencies, and injection, and present them as one deduplicated result. Section 3 and `MVP_PLAN.md` give the details.

---

## 1. Verified background: the five claims

| # | Claim as written | What the source actually says | Status | Corrected wording to use |
|---|---|---|---|---|
| 1 | "A 2025 Veracode study found security flaws in 45% of 80 AI coding tasks." | Veracode's *2025 GenAI Code Security Report* (30 Jul 2025) tested 100+ LLMs on 80 curated code-completion tasks. **45% of code samples** failed security tests and introduced OWASP Top 10 flaws. Java was worst at 72%. The denominator is **generated samples / test cases across all models**, not "45% of the 80 tasks." Flaws were detected with **Veracode's own static analyzer**. | **[Vendor claim]**, primary source located | "In Veracode's 2025 study of 100+ LLMs on 80 security-sensitive code-completion tasks, 45% of the generated code samples contained an OWASP Top 10 weakness, as judged by Veracode's static analysis." |
| 2 | "A 2025 scan found that 170 of 1,645 Lovable-built apps exposed user data." | Matt Palmer's statement on CVE-2025-48757: 1,645 projects from the **Lovable Launched showcase** were analyzed, and **170 (≈10.3%)** had **303** endpoints with inadequate RLS. The script checked **homepages only** and made **unauthenticated** requests, so true exposure may be higher. Exposed data included names, emails, phone numbers, API keys, payment details, and other PII. Scan done March 2025, published 29 May 2025. CVSS 9.3. | **[Independent]**, with a caveat: the researcher works at Replit, a Lovable competitor. CVE record confirmed. | "In 2025, a researcher scanned 1,645 apps from Lovable's public showcase and found 170 (about 10%) whose Supabase access rules let anonymous visitors read data, including names, emails, payment details, and API keys (CVE-2025-48757)." **Drop "home addresses"**: I could not confirm it in the primary source. |
| 3 | "GitGuardian found that AI-assisted commits leaked secrets at approximately twice the rate of human-only commits in 2025." | *State of Secrets Sprawl 2026* (published 17 Mar 2026, covers 2025): **Claude Code co-authored** public commits leaked secrets at **3.2%**, against a **1.5% baseline across all public GitHub commits**. The baseline is *all* commits, **not human-only**. The blog does not describe how AI commits were identified, and GitGuardian says the gap "should not be read as a simple tool failure." | **[Vendor claim]**, primary source located. The wording in the claim is **inaccurate**. | "GitGuardian reports that in 2025, public commits co-authored by Claude Code leaked secrets at about 3.2%, roughly twice the 1.5% rate across all public GitHub commits." |
| 4 | "GitHub reports that 80% of new developers use its AI coding assistant during their first week." | Octoverse 2025 (28 Oct 2025, data Sep 2024–Aug 2025): **nearly 80%** of new developers on GitHub use **Copilot** within their first week. | **[Vendor claim]**: GitHub measures adoption of its own paid product. | "GitHub reports that nearly 80% of developers new to GitHub use Copilot in their first week (Octoverse 2025)." |
| 5 | "India has approximately 2.19 crore developers on GitHub." | GitHub's India Octoverse 2025 announcement: **21.9 million** (= 2.19 crore) developers in India on GitHub, second only to the US, with 5.2M added that year. "Developers" means GitHub accounts, not verified professional developers. | **[Vendor claim]**, consistent across GitHub-sourced reports | "GitHub counts 21.9 million (2.19 crore) developer accounts in India, the second-largest after the US (Octoverse 2025)." |

**Sources:**
- Veracode press release: https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/ ; blog with per-language rates: https://www.veracode.com/blog/genai-code-security-report/
- Palmer statement: https://mattpalmer.io/posts/statement-on-CVE-2025-48757/ ; technical post: https://mattpalmer.io/posts/CVE-2025-48757/ ; NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-48757
- GitGuardian: https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/ ; report page: https://www.gitguardian.com/state-of-secrets-sprawl-report-2026
- Octoverse 2025: https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/
- India figure: https://www.business-standard.com/industry/news/github-india-57-million-developers-2030-ai-growth-125102801381_1.html (reports GitHub's announcement) **[Secondary for exact wording; figure consistent across outlets]**

**Stronger evidence to build the argument on** (independent, reproducible, exploit-based):
- **BaxBench** (ETH Zürich et al., ICML 2025): 392 backend tasks (28 scenarios × 14 frameworks), checked with functional tests **and expert-written end-to-end exploits**. https://arxiv.org/abs/2502.11844 **[Independent]**
- **SusVibes** (CMU et al., ICML 2026): 186 real-world feature requests on real repos, done by coding *agents*. SWE-Agent + Claude 4 Sonnet: 61% of solutions functionally correct, 10.5% secure. https://arxiv.org/abs/2512.03262 **[Independent]**
- **Lovable BOLA incident (2026):** reported 3 Mar 2026, published 20 Apr 2026. A free account could reach other users' projects, source code, and hardcoded Supabase credentials. The fix covered new projects only. https://thenextweb.com/news/lovable-vibe-coding-security-crisis-exposed **[Secondary]**

**Product implication [Inference]:** the best-supported, most AI-specific harm is not "AI writes SQL injection." Mature scanners catch that. The harm is **missing or wrong access control on data reachable from the browser**, plus **leaked keys**. Both Lovable incidents are authorization failures.

---

## 2. Landscape

### 2.1 Search strategy and selection rules

- **Searches:** primary docs and GitHub repos for each category in the brief. Recent (2025–2026) changelogs, advisories, and incident write-ups. Supabase community pages for RLS tooling. Academic benchmarks on AI code security.
- **Included:** tools that (a) cover JS/TS, Next.js, or Supabase, (b) can run locally or free for a student team, or (c) are a direct competitor to an "AI-agent security gate."
- **Excluded:** enterprise-only ASPM platforms with no free/local path (Checkmarx, Veracode platform, and others), IaC-only scanners (Checkov, KICS) because they are out of scope for an MVP with no IaC, and container-only scanners beyond a mention.
- **Stars are not quality.** Maintenance was judged from releases and changelogs where visible.

### 2.2 Broad shortlist (22)

| Category | Project | Type / licence | One-line relevance |
|---|---|---|---|
| Secrets | **Betterleaks** | OSS, MIT | Successor to Gitleaks by its original author. Gitleaks-compatible. Validation is optional. |
| Secrets | Gitleaks | OSS, MIT | Mature. Reported feature-complete in 2026 (security patches only). |
| Secrets | TruffleHog | OSS core AGPL-3.0 + commercial | Verifies keys against live provider APIs **by default**. |
| Secrets | GitGuardian ggshield | Proprietary platform, free tier | Strong detection. Needs a hosted account. |
| Secrets | GitHub secret scanning / push protection | Proprietary, free on public repos | Default safety net for public repos. |
| SAST | **Opengrep** | OSS, LGPL-2.1 | Community fork of Semgrep CE. Write your own rules here. |
| SAST | Semgrep CE / AppSec Platform | Engine LGPL-2.1; rules under Semgrep Rules License; platform proprietary | Best rule ecosystem. Rules licence restricts reuse in competing products. |
| SAST | CodeQL | Proprietary terms; free for public repos | Deep dataflow. Private repos need a paid licence. |
| SCA | **OSV-Scanner v2** | OSS, Apache-2.0 | Offline mode, npm guided remediation. |
| SCA | Dependabot / dependency review | Proprietary, free | Default for GitHub repos. |
| SCA | Trivy | OSS, Apache-2.0 | Broad scanner. Its supply chain was compromised in March 2026 (see §2.5). |
| SCA / malware | Socket | Proprietary, free tier | Malicious-package and slopsquatting detection. |
| DAST | **OWASP ZAP** | OSS, Apache-2.0 (not re-verified) | Active scanning plus an access-control testing add-on (alpha). |
| AuthZ / RLS | **Supabase splinter / Security Advisor** | OSS | Structural lints such as "RLS disabled" and "always-true write policy." |
| AuthZ / RLS | **basejump supabase-test-helpers** | OSS (licence not verified) | pgTAP helpers such as `tests.authenticate_as()`. Referenced in Supabase docs. |
| AuthZ / RLS | rlsautotest, rlsgrid, supashield, rls-scope, pgrls | Small OSS, mostly beta | Generate RLS test matrices or fuzz cross-tenant reads. |
| AI review | **anthropics/claude-code-security-review** | OSS, MIT; uses Claude API | LLM PR review plus a `/security-review` command. |
| AI review | GitHub Copilot Autofix / Copilot security review | Proprietary | Fixes for CodeQL alerts. |
| Agent integration | **Semgrep Guardian** | Proprietary plugin, hosted or local CLI | Hooks + MCP + skills for Claude Code, Codex, and Cursor. **Closest competitor.** |
| Agent integration | Snyk Studio / Snyk MCP | Proprietary | Security context and scans inside AI assistants. |
| Agent integration | GitHub security validation for coding agents | Proprietary, free | CodeQL, advisories, and secrets on agent-written PRs. |
| Builder guardrail | **Lovable security scans** | Proprietary | Quick scan on publish plus a deep agentic scan. |

### 2.3 Comparison matrix (shortlist, from documentation; **not tested**)

Legend: ✅ documented · ⚠️ partial / caveat · ❌ not documented (documented absence noted where found) · Local = can run with no code leaving the machine

| Tool | Detects | Notably does **not** address | Integration points | Local / data egress | Maintenance signal | Free / cost | MVP fit |
|---|---|---|---|---|---|---|---|
| Betterleaks | Hardcoded secrets in files and git history | Whether a key is client-exposed by design (e.g. Supabase anon key) | CLI, CI | ✅ Default scans make no provider calls. `-v`/`-a` call provider APIs. | Active. v2 on `main`. | Free | **Reuse** |
| TruffleHog | Secrets, plus live verification | Same as above | CLI, CI, pre-commit | ⚠️ Verifies by default, so the secret is sent to the provider. Disable with `--no-verification`. | Active | AGPL core | Optional. AGPL matters only if you distribute modified versions. |
| Opengrep | Pattern and taint rules you write | Authorization logic, RLS | CLI, CI | ✅ | Active fork | Free | **Reuse** for custom Next.js/Supabase rules |
| Semgrep CE / Guardian | SAST, SCA, secrets; Guardian scans each agent-written file | Docs do not mention authorization or RLS. Plugins use a fixed ruleset. | Hooks, MCP, skills, CI | ⚠️ Claude Code plugin uses Semgrep's **hosted** server by default. The docs page does not say what data is sent. | Very active | Free up to 10 contributors on the platform | **Compete or complement**, don't clone |
| CodeQL | Deep dataflow SAST | RLS, runtime authz | CI, GitHub | Runs in Actions | Active | Free on public repos only | Use if the repo is public |
| OSV-Scanner v2 | Known-vulnerable dependencies, licences | Malicious or new packages without an advisory | CLI, CI | ✅ Offline mode after DB download | Active (Google) | Free | **Reuse** |
| Socket | Malicious packages, slopsquatting | Code flaws | GitHub app, CLI, firewall | Hosted | Active | Free tier | Optional, for the pre-install check |
| ZAP | Runtime injection, headers, session issues; access-control add-on compares what each user can reach | Business-logic authz without configured rules. Add-on is alpha. | CLI, Docker, Automation Framework, GitHub Actions | ✅ Local | Very active (2026 monthly releases) | Free | Postpone. Heavy setup for students. |
| Supabase splinter | RLS disabled, RLS with no policy, security-definer views, exposed `auth.users`, always-true **write** policies | Whether a SELECT policy is too broad. `0024` covers UPDATE/DELETE/ALL and literal `true` forms only. | Studio, CLI (`supabase db lint`), MCP `get_advisors`, CI (open SQL) | ✅ Runs against your DB | Active, with open issue #165 and PR #169 for fail-open patterns | Free | **Reuse** as the structural layer |
| basejump test helpers + pgTAP | Lets you *write* RLS tests as specific users | Writes no tests itself | `supabase test db` | ✅ Local | Mature, small | Free | **Reuse** as the test runtime |
| rlsautotest / rlsgrid | Generated RLS allow/deny tests; cross-tenant fuzzing | App-layer API routes and `service_role` bypass in server code | CLI, CI, SARIF (rlsgrid) | ✅ Local | Beta (author statements) | Free (rlsautotest Apache-2.0 per author) | **Study, maybe reuse.** Proves the idea is not unique. |
| claude-code-security-review | LLM-judged vulns in PR diffs, including logic flaws | Proof. Findings are model opinions. | GitHub Action, `/security-review` | ⚠️ Sends code to the Claude API | Active | MIT; you pay API usage | Idea source. README says it is **not hardened against prompt injection.** |
| GitHub agent security validation | CodeQL, advisory DB, secrets on agent-authored code | RLS, runtime authz | GitHub cloud agents | Hosted | Shipped Oct 2025, extended to third-party agents Jun 2026 | Free (no GHAS licence needed) | Baseline that **already exists**. Don't duplicate. |
| Lovable scans | DB misconfig, missing RLS, "authorization gaps," deps; deep scan = agentic review | Only for Lovable apps. Says it can't guarantee security. | Built into Lovable | Hosted | Active | Included | Not reusable. Shows the market wants this. |

### 2.4 Deep inspections (8)

Each entry covers: what the evidence shows, the key strengths and limits with links, and what to reuse.

#### (1) Semgrep Guardian: the closest competitor
- **What it is:** bundles the Semgrep MCP server, hooks, and skills into one install. It scans every file an agent writes with Semgrep Code, Supply Chain, and Secrets, and returns findings so the agent can regenerate. Supports Claude Code, Codex, and Cursor (`afterFileEdit`/`stop` hooks). https://docs.semgrep.dev/guardian **[Vendor claim]**
- **Limits (from its own docs):** the Claude Code/Codex plugins use a **fixed ruleset** and don't apply org policies. Guardian "doesn't guarantee fixes." It complements CI rather than replacing it. The Guardian page does not mention authorization, Supabase, or RLS. That is not proof the feature is absent, only that it is not documented there.
- **Privacy:** the recommended Claude Code path uses Semgrep's **hosted remote server** with OAuth. A local CLI path exists.
- **Performance:** "95% of Guardian scans complete in under 5 seconds" (https://semgrep.dev/guardian/appsec) **[Vendor claim]**.
- **Implication [Inference]:** "hook + MCP + skill that scans what the agent writes" is **already a shipped product from a well-funded vendor.** A student team cannot win on that alone. Your earlier ProofGate design (skill + hook + MCP, 9 layers) overlaps heavily here. Differentiate on **what is checked** (authorization and isolation, with proof), not on **where it plugs in**.

#### (2) GitHub security validation for coding agents
- Copilot's cloud agent runs CodeQL, checks new dependencies against the Advisory DB, and runs secret scanning on code it writes, then tries to fix issues before opening the PR (https://github.blog/changelog/2025-10-28-copilot-coding-agent-now-automatically-validates-code-security-and-quality/). Since **9 June 2026** the same applies to **third-party coding agents**, with no GHAS licence required (https://github.blog/changelog/2026-06-09-security-validation-for-third-party-coding-agents). On 17 Nov 2026, Copilot's security-review specialist added on-demand secret scanning for developers and agents (https://github.blog/changelog/2026-11-17-secret-scanning-on-demand-for-developers-and-agents). **[Vendor claim]**
- **Implication:** a "PR security gate for secrets, injection, and dependencies" is becoming a **free default** on GitHub.

#### (3) Supabase splinter / Security Advisor: the structural RLS baseline
- Open-source SQL lints behind Supabase's Security Advisor (https://github.com/supabase/splinter). Also exposed via the Supabase MCP `get_advisors` tool (https://supabase.com/docs/guides/monitoring-and-debugging/advisors.md).
- Supabase now emails owners when tables are created with RLS disabled, and the Table Editor shows a warning label (https://supabase.com/blog/supabase-security-2025-retro).
- **Key limitation (documented by third parties, consistent with upstream issues):** `0024_rls_policy_always_true` covers UPDATE/DELETE/ALL only and matches literal always-true forms. SELECT policies such as `using (true)` are skipped on purpose, because public reads are often intended. Upstream issue #165 / PR #169 (June 2026) propose detecting fail-open `auth.uid() IS NULL` patterns (https://www.guardlayer.io/blog/supabase-rls-policy-fails-open-auth-uid-null) **[Secondary]**. A third-party study of public Supabase repos found 48.6% had an anon `SELECT … using (true)` policy (https://levelup.gitconnected.com/how-often-public-supabase-repos-leave-a-table-readable-by-the-anon-key-b9ae507a8d89) **[Secondary; method not verified]**.
- **Implication:** a linter cannot know whether `profiles` *should* be public. **That needs application intent plus a runtime test.**
- **Reuse:** run splinter SQL against the local DB as layer 1 of the authz check.

#### (4) pgTAP + basejump supabase-test-helpers: the test runtime
- Supabase docs recommend pgTAP for proving each RLS policy "allows and blocks what you meant" and show `supabase test db` (https://supabase.com/docs/guides/database/postgres/testing-row-level-security). The basejump helpers add `tests.create_supabase_user()`, `tests.authenticate_as()`, `tests.clear_authentication()`, and `tests.rls_enabled()` (https://github.com/usebasejump/supabase-test-helpers).
- Supabase docs also show the same checks through `@supabase/supabase-js` + Vitest. That matters because **app-level tests go through PostgREST the way the real app does** (same page).
- **Limit:** you must write every test by hand. The rlsautotest author calls hand-written RLS tests something that "mostly gets skipped" (https://supabase.com/contribute/t/860-66969-11493-reddit_post_1ucizps) **[Independent, author opinion]**.
- **Reuse:** generated tests should **emit standard pgTAP files and Vitest files** that live in the user's repo and keep running without your product.

#### (5) Small RLS test generators (rlsautotest, rlsgrid, supashield, rls-scope, pgrls)
- **rlsautotest** (Apache-2.0, beta): reads policies, generates pgTAP tests plus seed data, includes a CI gate (author post above). **rlsgrid**: builds a role × table × operation matrix, emits pgTAP, runs a cross-tenant fuzz, outputs SARIF (https://pypi.org/project/rlsgrid/). **rls-scope**: AI-generated pgTAP tests; last pushed Nov 2024 (https://awesome.ecosyste.ms/projects/github.com%2Fxaac-ai%2Frls-scope).
- **Strengths:** they prove that generating RLS tests from the schema works.
- **Limits [Inference from their READMEs/posts]:** database-only. They don't follow the **Next.js route handler or server action that uses `service_role`**, which bypasses RLS entirely. They don't know which tables are *meant* to be public. They aren't part of the AI agent's edit loop.
- **Implication:** **"RLS test generator" alone is not a differentiator.** The differentiator is combining it with app routes, intent capture, the agent loop, and fix verification.

#### (6) anthropics/claude-code-security-review: LLM review
- MIT-licensed GitHub Action plus a `/security-review` command. Semantic review that can catch logic flaws (https://github.com/anthropics/claude-code-security-review).
- **Documented limit:** "This action is not hardened against prompt injection attacks and should only be used to review trusted PRs" (README mirror: https://gitea.com/anthropics/claude-code-security-review). A Checkmarx experiment reported by The Register got crafted code past the review as "security impact: none" (https://www.theregister.com/2025/09/09/ai_security_review_risks/) **[Secondary]**. Microsoft documented CI secret exposure risks with the related Claude Code Action (https://microsoft.com/en-us/security/blog/2026/06/05/securing-ci-cd-in-agentic-world-claude-code-github-action-case).
- **Implication:** **LLM findings must not block shipping on their own.** Use LLMs to explain, guess intent, and draft fixes. Block only on deterministic or proven evidence.

#### (7) OSV-Scanner v2 + Betterleaks: commodity layers to reuse
- **OSV-Scanner:** offline scanning after a DB download. Guided remediation for npm, with an explicit warning that `fix` can be risky on untrusted projects because it may run package-manager scripts (https://github.com/google/osv-scanner).
- **Betterleaks:** MIT, by the Gitleaks author, maintained by multiple people. Default scans make no provider calls; validation is opt-in (https://github.com/betterleaks/betterleaks; https://www.aikido.dev/blog/betterleaks-gitleaks-successor). Gitleaks is reported as feature-complete (https://trevorlasn.com/blog/your-repo-is-a-leaky-ship-probably) **[Secondary]**.
- **Reuse plan:** call both as subprocesses with pinned versions and checksums. Parse JSON/SARIF into one finding format. Never run `osv-scanner fix` automatically.

#### (8) Lovable's built-in scans: builder guardrails
- 2025: Security Scan (integrates Supabase Security Advisor), Security Reviewer, and API key protection (https://lovable.dev/blog/secure-vibe-coding). 2026: an automatic basic scan on publish (~10–15 s), covering DB misconfig, missing RLS, and "authorization gaps," with opt-in auto-fix and publish blocking. A deep scan is an AI code review taking ~2–4 min (https://lovable.dev/blog/how-lovable-protects-your-apps-automatically). The docs say these "cannot guarantee complete security" (https://docs.lovable.dev/features/security). **[Vendor claim]**
- **Independent criticism:** Palmer said the 2025 scanner only checked that *a* policy exists (statement above). A 2026 audit of 62 Lovable apps reported 63% with critical/high findings and said the checker "struggles with false positives" (https://medium.com/@jacobp96/i-scanned-over-50-lovable-apps-for-security-vulnerabilities-d05b2ad94006) **[Independent blog; method not verified]**.
- **Implication:** builders are adding guardrails, but only for their own platform. Developers using **Claude Code / Cursor on their own Next.js + Supabase repo** don't get them.

### 2.5 Cross-cutting risks found during research

- **Security tools are supply-chain targets.** On 19 Mar 2026, attackers force-pushed malicious code to 76 of 77 `aquasecurity/trivy-action` tags and published malicious Trivy v0.69.4. The root cause was credentials stolen in an earlier compromise (https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23; https://www.aquasec.com/blog/trivy-supply-chain-attack/). **Design rule:** pin every third-party binary and Action by version + checksum/SHA, and never auto-update the scanners.
- **Agents with database keys plus untrusted text equal data theft.** General Analysis showed a Cursor + Supabase MCP setup, running with `service_role`, could be tricked by a support-ticket message into leaking an `integration_tokens` table (https://generalanalysis.com/blog/supabase-mcp-blog; analysis: https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/). Supabase says there has been no reported customer incident (https://supabase.com/blog/defense-in-depth-mcp). **Design rule:** the product's own MCP server must never hold `service_role` for a remote project, must treat all file contents as data, and must have no network-sending tool.
- **Middleware-only auth is fragile in Next.js.** CVE-2025-29927 let a crafted `x-middleware-subrequest` header skip middleware authorization in self-hosted Next.js before 14.2.25 / 15.2.3 (https://nvd.nist.gov/vuln/detail/CVE-2025-29927). **Design rule:** check authorization in each route handler or server action, or in RLS, not only in middleware.
- **Slopsquatting.** LLMs invent package names. In a USENIX Security 2025 study, 43% of hallucinated names reappeared in all 10 repeated runs (https://socket.dev/glossary/slopsquatting). No confirmed mass-exploitation campaign had been reported as of the CSA note (https://labs.cloudsecurityalliance.org/research-rb/csa-research-note-slopsquatting-ai-coding-assistant-supply-c/). **Design rule:** a cheap "does this package exist, how old is it, how many downloads?" check before the agent installs anything.
- **LLM data handling.** On the Gemini API free tier, content is "used to improve our products"; on the paid tier it is not (https://ai.google.dev/pricing). **Design rule:** never send user code to a free-tier LLM endpoint. Redact first, send minimal snippets, and allow a no-LLM mode.

---

## 3. Product gap analysis

### 3.1 What is already solved well
| Problem | Solved by | Confidence |
|---|---|---|
| Known secret formats in code/history | Betterleaks/Gitleaks, TruffleHog, GitHub push protection | High |
| Known-vulnerable dependencies | OSV-Scanner, Dependabot | High |
| Common injection/XSS patterns | Semgrep/Opengrep, CodeQL | High for patterns, medium for cross-file flows |
| Scanning agent-written files in the agent loop | Semgrep Guardian, Snyk Studio, GitHub agent validation | High (vendor-documented) |
| Structural RLS mistakes (RLS off, no policy) | Supabase splinter + dashboard alerts | High |

### 3.2 Gaps that hurt most in AI-assisted development
1. **Wrong-but-present access control.** RLS is on, but the policy is too broad, or the API route uses `service_role` and never checks ownership. Linters can't judge intent, and LLM reviewers can't prove it. *(Lovable 2025 RLS, Lovable 2026 BOLA, splinter's deliberate SELECT exemption.)*
2. **No proof, so findings get ignored.** Developers who didn't write the code can't judge a "possible IDOR" warning. Showing "Bob just read Alice's note: here is the request" is what changes behaviour **[Inference; needs user testing]**.
3. **Fix loops without verification.** Agents "fix" by deleting features or adding a check that doesn't run on the real path. Lovable's own checker was reported to sometimes go "in circles" on fixes (Medium audit above). Nobody re-runs the *same* exploit after the fix.
4. **Client-exposed keys by design.** Supabase anon keys are meant to be public. `service_role` keys are not. Generic secret scanners flag both or neither. Classifying them takes stack awareness.
5. **Too many separate tools.** A student would have to install and understand 4–5 tools with different outputs.

### 3.3 Why a developer would use this instead of combining tools
Only if it does something they can't easily assemble: **"one command (or automatic hook) that proves whether one user can touch another user's data in my Next.js + Supabase app, and confirms the fix."** Bundling and deduplicating secrets, dependency, and injection results is a convenience, not a moat.

### 3.4 What a small team can credibly deliver
- A local runner against `supabase start` (Docker), using 2–3 generated identities and replay through supabase-js plus the app's own `fetch` routes.
- A table-intent file (`proofgate.yml`: `public` / `owner` / `tenant` per table), with an LLM-*suggested* first draft that a human confirms.
- Thin wrappers around Betterleaks, OSV-Scanner, and Opengrep with ~15 custom rules for Next.js + Supabase.
- A Claude Code hook + MCP tool that returns compact, structured findings.

### 3.5 Where custom work would be wasteful or risky
- Writing your own secret regexes, CVE database, or general SAST engine: wasteful.
- LLM-only vulnerability detection used for blocking: risky (prompt injection, false positives).
- Scanning **remote/production** Supabase projects or third-party apps: risky legally and ethically. Restrict the MVP to local stacks and preview environments the user owns.
- Auto-applying fixes to RLS or auth without a human-approved diff and a re-test: risky.
- Holding user `service_role` keys or source code on your server: a privacy and liability risk. Stay local-first.

---

## 4. Product approach comparison

Scores are 1 (poor) to 5 (strong). They are my judgement, with the reason given for each. They are not measurements.

| Criterion | A. Local CLI / pre-commit scanner bundle | B. Agent integration (hook + MCP + skill) running generic scanners | C. PR / preview-deployment gate | **D. Recommended: agent-triggered local isolation proof (B's delivery + new authz engine, with A as fallback)** |
|---|---|---|---|---|
| User value | 3: useful, but duplicates free tools | 3: convenient, but duplicates Guardian/GitHub | 3: catches issues late; students rarely have preview DBs with test users | **5**: answers the scariest question with proof |
| Feasibility (4–6 wk) | 5 | 4 | 3: preview infra, secrets in CI | **4**: hard parts are identity seeding and route discovery, and both can be narrowed |
| Differentiation | 1 | 2: Semgrep Guardian exists | 2: GitHub validation exists | **4**: small RLS tools exist, but none link app routes + agent loop + fix re-test (documented gap, not exhaustive) |
| Developer friction | 4 | 5: invisible until a finding | 3: waits for CI | **4**: needs Docker + `supabase start` the first time |
| Privacy | 5 | 3–5, depending on hosted scanners | 3: CI holds secrets | **5**: local only. LLM optional and redacted. |
| Operating cost | 5 | 4 | 4 | **5**: runs on the user's machine |
| Evaluation difficulty | 4: easy to benchmark | 3 | 3 | **3**: needs fixture apps with multiple users. Doable, see §6 of MVP_PLAN. |
| **Total (35)** | 27 | 24–26 | 21 | **30** |

**Weak ideas, stated plainly:**
- "9-layer scanner" as the pitch: judges and users will see bundled Gitleaks/Semgrep/OSV. Collapse it to **one promise plus supporting checks**.
- "AI finds all vulnerabilities": not credible, and the research above contradicts it.
- "Certified secure" badges: dishonest. A scan cannot prove security.

### 4.1 Recommendation
- **Target user:** a student or indie developer building a **Next.js (App Router) + Supabase** app with **Claude Code or Cursor**, with real user sign-in, before the first public launch.
- **Workflow:** the agent finishes a change → a hook runs `proofgate check --changed` (fast static + structural, under ~10 s) → before "ship" (or on demand), `proofgate prove` spins up identities on the local Supabase stack and replays reads and writes across users → proven leaks return to the agent with a reproducible test → the agent proposes a fix → ProofGate re-runs the same test → the human approves the diff.
- **Narrow promise:** *"Before you ship, ProofGate shows you, with a reproducible test, whether one signed-in user can read or change another user's data in your Next.js + Supabase app, and checks that the fix actually works. It also catches leaked server keys."*

### 4.2 Assumptions that need interviews or experiments
1. Student/indie builders will run Docker + `supabase start` locally. *(Many use only hosted Supabase. Experiment: survey 15 builders. Fallback: a free Supabase branch/preview project they own.)*
2. A proven leak changes behaviour more than a warning. *(A/B test with 8–10 developers: proof vs plain warning.)*
3. Developers will confirm a per-table intent file. *(Measure the completion rate. LLM pre-fill plus a one-keystroke confirm.)*
4. Route discovery from Next.js file conventions covers most data paths in AI-generated apps. *(Measure on 10 agent-generated apps.)*
5. The agent can fix RLS correctly when given a failing test. *(Measure the fix pass rate and regressions.)*

---

## 5. Reusable components and integration work

| Component | Reuse for | Integration work | Licence note |
|---|---|---|---|
| Betterleaks | Secret detection | Subprocess, JSON parsing, pinned binary + checksum, redact matches before storing | MIT, fine |
| OSV-Scanner | Dependency CVEs | Subprocess on lockfile. Offline DB cache. Never auto-run `fix`. | Apache-2.0 (per pkg listing) |
| Opengrep | Custom TS/Next.js rules | Write your own rules. **Don't bundle Semgrep-registry rules** in a product that might compete, because the Semgrep Rules License limits them to internal, non-competing, non-SaaS use (https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss). | LGPL-2.1 engine. Run it as a separate binary to avoid linking questions. |
| Supabase CLI + splinter SQL | Local stack, structural lints | `supabase start`, run lint SQL, parse rows | Check splinter LICENSE (not verified here) |
| pgTAP + basejump helpers | Emitted regression tests | Generate `.sql` test files into the user's `supabase/tests/` | Check licence (not verified here) |
| @supabase/supabase-js + Vitest | App-path replay and emitted tests | Sign in test users, call PostgREST and app routes | MIT (well known; not re-verified) |
| rlsautotest / rlsgrid | Ideas, possibly policy parsing | Read the code before reuse. They are beta. | Apache-2.0 (rlsautotest, per author) |

---

## 6. Citations index (all accessed 20 Nov 2026)

Background: Veracode PR https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/ · Veracode blog https://www.veracode.com/blog/genai-code-security-report/ · Palmer https://mattpalmer.io/posts/statement-on-CVE-2025-48757/ · NVD https://nvd.nist.gov/vuln/detail/CVE-2025-48757 · GitGuardian https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/ · Octoverse https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/ · India https://www.business-standard.com/industry/news/github-india-57-million-developers-2030-ai-growth-125102801381_1.html · BaxBench https://arxiv.org/abs/2502.11844 · SusVibes https://arxiv.org/abs/2512.03262 · Lovable 2026 BOLA https://thenextweb.com/news/lovable-vibe-coding-security-crisis-exposed

Tools: Semgrep Guardian https://docs.semgrep.dev/guardian · Semgrep pricing https://semgrep.dev/pricing · Semgrep rules licence https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss · Opengrep comparison https://semgrep.dev/docs/faq/comparisons/opengrep · Betterleaks https://github.com/betterleaks/betterleaks · TruffleHog verification default https://particula.tech/blog/gitleaks-vs-trufflehog-vs-betterleaks · OSV-Scanner https://github.com/google/osv-scanner · Trivy advisory https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23 · ZAP access control add-on https://zaproxy.org/docs/desktop/addons/access-control-testing · ZAP marketplace https://zaproxy.org/addons · splinter https://github.com/supabase/splinter · Supabase RLS testing https://supabase.com/docs/guides/database/postgres/testing-row-level-security · Supabase security retro https://supabase.com/blog/supabase-security-2025-retro · basejump helpers https://github.com/usebasejump/supabase-test-helpers · rlsautotest https://supabase.com/contribute/t/860-66969-11493-reddit_post_1ucizps · rlsgrid https://pypi.org/project/rlsgrid/ · Claude Code security review https://github.com/anthropics/claude-code-security-review · GitHub agent validation https://github.blog/changelog/2026-06-09-security-validation-for-third-party-coding-agents · Copilot agent validation https://github.blog/changelog/2025-10-28-copilot-coding-agent-now-automatically-validates-code-security-and-quality/ · CodeQL private repo requirement https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/troubleshooting/troubleshooting-analysis-errors/cannot-enable-codeql-in-a-private-repository · Snyk Studio https://snyk.io/blog/snyk-studio-announcement/ · Lovable scans https://lovable.dev/blog/how-lovable-protects-your-apps-automatically · Lovable docs https://docs.lovable.dev/features/security

Risks: Supabase MCP exfiltration https://generalanalysis.com/blog/supabase-mcp-blog · Supabase response https://supabase.com/blog/defense-in-depth-mcp · CVE-2025-29927 https://nvd.nist.gov/vuln/detail/CVE-2025-29927 · Slopsquatting https://socket.dev/glossary/slopsquatting · Gemini data use https://ai.google.dev/pricing · Splinter 0024 scope https://www.guardlayer.io/blog/supabase-rls-policy-fails-open-auth-uid-null
