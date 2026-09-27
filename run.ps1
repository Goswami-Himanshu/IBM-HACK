Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  BobSpec-Provenance: Autonomous Compliance Verifier"
Write-Host "  IBM Bob 2.0 Agentic Architecture + Tamper-Evident Audit Ledger"
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

Write-Host ""
Write-Host "Installing Node.js dependencies (for MCP server)..." -ForegroundColor Yellow
npm install

Write-Host ""
Write-Host "Starting Web Dashboard at http://127.0.0.1:8000" -ForegroundColor Green
python run_server.py
