"""
BobSpec-Provenance Web Server Runner
Launches the integrated compliance verifier + provenance ledger dashboard.
"""

import sys
from pathlib import Path
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent))

if __name__ == "__main__":
    print("=" * 70)
    print("  BobSpec-Provenance: Autonomous Compliance Verifier")
    print("  IBM Bob 2.0 Agentic Architecture + Tamper-Evident Audit Ledger")
    print("=" * 70)
    print("Web Dashboard:    http://127.0.0.1:8000")
    print("MCP Server:       node mcp_server.js")
    print("Ledger Path:      ./data/ledger.jsonl")
    print()
    uvicorn.run("bob_verifier.web.app:app", host="127.0.0.1", port=8000, reload=False)
