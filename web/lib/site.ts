// Facts used by several pages. The statistics are worded exactly as in the final plan (section 13.3); the limits statement
// is the verbatim sentence from section 1. Do not "improve" them: overclaiming is the thing this product exists to avoid.

export const LIMITS_STATEMENT =
  "Passing ProofGate means our attacks failed on the routes and tables we tested. It doesn't mean your app is secure.";

export const PITCH =
  "Other scanners show you warnings. ProofGate shows you the stolen data, and only accepts a fix that provably stops it.";

export const STATS: { text: string; source: string }[] = [
  {
    text: "In Veracode's 2025 study of 100+ LLMs on 80 security-sensitive coding tasks, 45% of generated code samples had an OWASP Top 10 flaw.",
    source: "Veracode, 2025",
  },
  {
    text: "A researcher scanned 1,645 apps from Lovable's showcase and found 170 (about 10%) that let anonymous visitors read data such as emails, payment details, and API keys (CVE-2025-48757).",
    source: "CVE-2025-48757",
  },
  {
    text: "GitGuardian: in 2025, Claude Code co-authored public commits leaked secrets at 3.2% versus 1.5% for all public commits, about 2x.",
    source: "GitGuardian, 2025",
  },
  {
    text: "SusVibes (ICML 2026): an agent's solutions were 61% functionally correct but only 10.5% secure.",
    source: "SusVibes, ICML 2026",
  },
];

export const LAYERS: { n: number; name: string; what: string; tool: string }[] = [
  { n: 1, name: "Secrets", what: "Live keys and service_role keys in code, blocked as they are written", tool: "Betterleaks + JWT role decoder" },
  { n: 2, name: "Code patterns", what: "String-built SQL, shell=True, debug mode, auth only in middleware", tool: "Semgrep + ProofGate rules + Bandit" },
  { n: 3, name: "Dependencies", what: "Known-vulnerable packages, with the fixed version", tool: "OSV-Scanner + pip-audit + npm audit" },
  { n: 4, name: "Fake packages", what: "Packages that do not exist, are brand new, or look like typos", tool: "Registry check + cache" },
  { n: 5, name: "Database policies", what: "Row-level security that is off, or checks the role instead of the owner", tool: "Splinter + contract-aware checks" },
  { n: 6, name: "Config", what: "Committed .env files, secrets in NEXT_PUBLIC_ names, open CORS", tool: "Checkov + ProofGate checks" },
  { n: 7, name: "Running app", what: "A local scan of the running app", tool: "ZAP baseline (localhost only)" },
  { n: 8, name: "Proof", what: "Attack the app as a second user and show the stolen data", tool: "The Doppelganger probe (built here)" },
  { n: 9, name: "Browser bundle", what: "Secrets and source maps in what ships to visitors", tool: "Bundle scan" },
];

export const BLIND_SPOTS = [
  "multi-step flows",
  "routes that need complex request bodies",
  "lookups by something other than an id (for example ?email=)",
  "storage buckets",
  "edge functions",
  "business logic",
  "payments",
];
