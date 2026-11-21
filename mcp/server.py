"""ProofGate MCP server entry point (plan section 15 layout).

The implementation lives in the installable package (`proofgate.mcpserver`) so that `pip install proofgate-ai` provides the
`proofgate-mcp` command. This file only lets you run it from a checkout:  python mcp/server.py
"""
from proofgate.mcpserver import main

if __name__ == "__main__":
    main()
