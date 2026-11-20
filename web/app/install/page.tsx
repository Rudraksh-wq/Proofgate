export const metadata = { title: "Install ProofGate" };

const MCP_JSON = `{
  "mcpServers": {
    "proofgate": { "command": "proofgate-mcp", "args": [] }
  }
}`;

const CODEX_TOML = `[mcp_servers.proofgate]
command = "proofgate-mcp"
args = []`;

export default function Install() {
  return (
    <>
      <h1>Install</h1>
      <p className="lede">Pick the way you work. All of them use the same engine, and all of them run on your machine.</p>
      <div className="tabs" role="navigation" aria-label="Install options">
        <a href="#claude-code">Claude Code plugin</a>
        <a href="#mcp">MCP (Claude Code, Cursor, Codex, Windsurf)</a>
        <a href="#cli">Command line</a>
        <a href="#troubleshooting">Troubleshooting</a>
      </div>

      <section className="panel" id="claude-code">
        <h2>Claude Code plugin</h2>
        <p>This adds the hook that blocks live keys as they are written, the six-tool MCP server, three skills and three slash commands.</p>
        <ol className="steps">
          <li>Install the engine: <code>pipx install proofgate</code></li>
          <li>In Claude Code: <code>/plugin marketplace add Rudraksh-wq/Proofgate</code></li>
          <li>Then: <code>/plugin install proofgate@proofgate</code></li>
          <li>Check the setup: <code>proofgate doctor</code></li>
          <li>Try it: <code>/proofgate-scan</code>, then <code>/proofgate-prove</code></li>
        </ol>
      </section>

      <section className="panel" id="mcp">
        <h2>MCP server</h2>
        <p>First install the engine (<code>pipx install proofgate</code>). The server speaks MCP over stdio and has exactly six tools: <code>get_contract</code>, <code>scan_file</code>, <code>scan_project</code>, <code>prove</code>, <code>verify_fix</code>, <code>explain_finding</code>. It has no shell tool, no network-send tool and no URL inputs.</p>
        <h3>Claude Code, Cursor and Windsurf</h3>
        <pre><code>{MCP_JSON}</code></pre>
        <ul>
          <li><b>Claude Code:</b> save as <code>.mcp.json</code> in your project, or use the plugin above.</li>
          <li><b>Cursor:</b> save as <code>.cursor/mcp.json</code>. Or run <code>proofgate init --agent cursor</code>, which also adds the hooks and rules.</li>
          <li><b>Windsurf:</b> merge into <code>~/.codeium/windsurf/mcp_config.json</code>. <code>proofgate init --agent windsurf</code> writes the snippet and the project rules; it never edits your home folder.</li>
        </ul>
        <h3>Codex</h3>
        <pre><code>{CODEX_TOML}</code></pre>
        <p>Put it in <code>.codex/config.toml</code> (trusted projects) or <code>~/.codex/config.toml</code>. <code>proofgate init --agent codex</code> does this and adds the rules to <code>AGENTS.md</code>. Codex has no hook system, so the MCP tools and rules do the gating.</p>
      </section>

      <section className="panel" id="cli">
        <h2>Command line</h2>
        <pre><code>{`pipx install proofgate
proofgate init            # detect the stack, draft the contract, write agent files
proofgate scan .          # fast layers; add --full to also attack the app locally
proofgate prove .         # attack the app as a second user (local only)
proofgate fix . --finding <id>`}</code></pre>
        <p>Exit codes: <code>0</code> nothing at or above <code>--fail-on</code>, <code>1</code> findings, <code>2</code> a tool failed (never treated as clean).</p>
      </section>

      <section className="panel" id="troubleshooting">
        <h2>Troubleshooting</h2>
        <p>Run <code>proofgate doctor</code>. It lists every external tool, checks its version and SHA-256 against <code>tools.lock.json</code>, and refuses to run a binary that does not match. A tool that is not installed is skipped and recorded in the report, never silently ignored.</p>
        <ul>
          <li><b>&ldquo;skipped: not installed&rdquo;</b>: install that tool, then <code>proofgate doctor --pin &lt;tool&gt;</code> to record it as trusted.</li>
          <li><b>The probe cannot start your app:</b> ProofGate runs <code>python app.py</code> with <code>PORT</code> and <code>DB_PATH</code> set. Make sure those two variables are read and that Flask is installed in the same Python.</li>
          <li><b>Offline:</b> set <code>PROOFGATE_OFFLINE=1</code>. Nothing is sent anywhere; only cached package lookups are used.</li>
        </ul>
      </section>
    </>
  );
}
