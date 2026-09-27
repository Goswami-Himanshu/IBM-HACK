@echo off
echo ================================================================
echo  BobSpec-Provenance: Autonomous Compliance Verifier
echo  IBM Bob 2.0 Agentic Architecture + Tamper-Evident Audit Ledger
echo ================================================================
echo.
echo Installing Python dependencies...
pip install -r requirements.txt
echo.
echo Installing Node.js dependencies (for MCP server)...
npm install
echo.
echo Starting Web Dashboard at http://127.0.0.1:8000
python run_server.py
