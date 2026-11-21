# ProofGate for Claude Code

1. Install the engine: `pipx install proofgate-ai` (it provides the `proofgate` and `proofgate-mcp` commands). To run only the MCP server: `claude mcp add proofgate --scope user -- proofgate-mcp`, or `uvx --from proofgate-ai proofgate-mcp`.
2. In Claude Code: `/plugin marketplace add Rudraksh-wq/Proofgate`
3. Then: `/plugin install proofgate@proofgate`
4. Check the setup: `proofgate doctor`
5. Try it: `/proofgate-scan`, then `/proofgate-prove`

The plugin adds a hook that blocks live keys as they are written, a six-tool MCP server, three skills and three slash commands. Everything runs on your machine. Passing ProofGate means its attacks failed on the routes and tables it tested; it does not mean your app is secure.
