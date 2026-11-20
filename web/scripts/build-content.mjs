// Generates the machine-readable files from the repository's own sources, so they cannot drift from the product:
//   public/llms-full.txt, public/limits.md, public/benchmark.md, public/docs/agent-workflow.md, public/docs/mcp-tools.md,
//   public/schemas/*.v1.json
// public/llms.txt is hand-written (and linted by the tests): it must never tell an agent to disable hooks, skip confirmation
// or send code anywhere.
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = join(dirname(fileURLToPath(import.meta.url)), "..");
const repo = join(web, "..");
const pub = join(web, "public");
mkdirSync(join(pub, "docs"), { recursive: true });
mkdirSync(join(pub, "schemas"), { recursive: true });

const LIMITS = "Passing ProofGate means our attacks failed on the routes and tables we tested. It doesn't mean your app is secure.";
const BLIND_SPOTS = ["multi-step flows", "routes that need complex request bodies", "lookups by something other than an id (for example ?email=)", "storage buckets", "edge functions", "business logic", "payments"];

// --- schemas
const schemaDir = join(repo, "schemas");
for (const f of readdirSync(schemaDir).filter((n) => n.endsWith(".v1.json"))) copyFileSync(join(schemaDir, f), join(pub, "schemas", f));
const findingSchema = readFileSync(join(schemaDir, "finding.v1.json"), "utf8");

// --- the agent workflow = the main skill, minus its frontmatter
const skill = readFileSync(join(repo, "plugin", "skills", "proofgate", "SKILL.md"), "utf8");
const workflow = skill.replace(/^---\n[\s\S]*?\n---\n/, "").trim();
const agentWorkflow = `# ProofGate agent workflow\n\n${workflow}\n`;
writeFileSync(join(pub, "docs", "agent-workflow.md"), agentWorkflow);

// --- MCP tools, read from the server's own docstrings
const src = readFileSync(join(repo, "core", "proofgate", "mcpserver.py"), "utf8");
const tools = [...src.matchAll(/async def (\w+)\(([^)]*)\) -> str:\n\s+"""([\s\S]*?)"""/g)].map((m) => ({
  name: m[1],
  params: m[2].split(",").map((p) => p.trim()).filter((p) => p && !p.startsWith("ctx")).map((p) => p.split(":")[0].trim()),
  doc: m[3].replace(/\s+/g, " ").trim(),
}));
if (tools.length !== 6) throw new Error(`expected 6 MCP tools in mcpserver.py, found ${tools.length}`);
const securityProps = [
  "no shell tool, no network-send tool, no URL inputs, no remote database credentials",
  "project_dir must be inside the client's workspace roots",
  "all project text is returned inside an UNTRUSTED_DATA block built from structured fields, after redaction",
  "nothing changes a finding's status except a re-run of the checks; explain_finding is text only",
  "verify_fix applies patches only in a temporary copy",
];
const mcpTools =
  `# ProofGate MCP tools\n\nStart the server with \`proofgate-mcp\` (stdio).\n\n` +
  tools.map((t) => `## ${t.name}(${t.params.join(", ")})\n\n${t.doc}\n`).join("\n") +
  `\n## Security properties\n\n${securityProps.map((p) => `- ${p}`).join("\n")}\n`;
writeFileSync(join(pub, "docs", "mcp-tools.md"), mcpTools);

// --- limits
const limitsMd = `# What ProofGate cannot prove\n\n${LIMITS}\n\n## Known blind spots\n\n${BLIND_SPOTS.map((b) => `- ${b}`).join("\n")}\n\n` +
  `## Other limits\n\n- "Proven" means proven against your contract; a wrong contract or seed can still mislead.\n- Untested is not safe: anything that could not be set up is listed as untested.\n- Layer 7 is not built yet.\n- The benchmark is small and synthetic.\n`;
writeFileSync(join(pub, "limits.md"), limitsMd);

// --- benchmark (measured numbers only, from bench/results.json)
const r = JSON.parse(readFileSync(join(repo, "bench", "results.json"), "utf8"));
const f2 = (x) => (x === null || x === undefined ? "n/a" : x.toFixed(2));
const rows = Object.entries(r.tables).map(([name, t]) =>
  t.available ? `| ${name} | ${f2(t.overall.precision)} | ${f2(t.overall.recall)} | ${f2(t.overall.f1)} | ${f2(t.by_category.access.recall)} |` : `| ${name} | not measured: ${t.reason} | | | |`);
const benchmarkMd =
  `# ProofGate benchmark\n\nMeasured ${r.generated_at.slice(0, 10)} on ${r.corpus.apps} small synthetic Flask apps (${r.corpus.ground_truth_items} planted flaws). ` +
  `This shows how ProofGate does on this corpus, not on real apps. ${r.heldout.apps === 0 ? "No held-out set has been provided, so there is no held-out number." : ""}\n\n` +
  `| column | precision | recall | F1 | access recall |\n|---|---|---|---|---|\n${rows.join("\n")}\n\n` +
  `Fix verification on ${r.fix_verification.cases} fixes: re-scan-says-clean ${f2(r.fix_verification.rescan_accuracy)}, tournament ${f2(r.fix_verification.tournament_accuracy)} (${r.fix_verification.tournament_correct}).\n\n` +
  `Method: bench/README.md. Re-run: python bench/run_bench.py\n`;
writeFileSync(join(pub, "benchmark.md"), benchmarkMd);

// --- everything in one file
const llmsFull = [
  "# ProofGate (full documentation)",
  "",
  "> ProofGate is a local security gate for AI-written web apps (Python/Flask, Next.js + Supabase). It runs 9 layers of checks, proves access-control bugs by attacking the app as a second user on a local throwaway database, and only accepts fixes that stop the attack while the owner's feature still works. Nothing is uploaded; the website does not scan code.",
  "",
  "## Install",
  "",
  "- Claude Code plugin: `/plugin marketplace add Rudraksh-wq/Proofgate`, then `/plugin install proofgate@proofgate` (install the engine first: `pipx install proofgate`).",
  '- MCP server: `{"mcpServers":{"proofgate":{"command":"proofgate-mcp"}}}`',
  "- CLI: `pipx install proofgate && proofgate init`; check the setup with `proofgate doctor`.",
  "",
  mcpTools.replace(/^# /, "## ").replace(/^## /gm, "### ").replace(/^### ProofGate MCP tools/, "## MCP tools"),
  "",
  "## Finding JSON schema (proofgate.finding/v1)",
  "",
  "```json",
  findingSchema.trim(),
  "```",
  "",
  agentWorkflow.replace(/^# /, "## ").replace(/^## ProofGate agent workflow/, "## Agent workflow"),
  "",
  "## Limits",
  "",
  LIMITS,
  "",
].join("\n");
writeFileSync(join(pub, "llms-full.txt"), llmsFull);
console.log(`content: ${tools.length} tools, ${readdirSync(join(pub, "schemas")).length} schemas, llms-full.txt ${llmsFull.length} bytes`);
