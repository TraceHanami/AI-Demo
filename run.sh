#!/usr/bin/env bash
# Startup script for Customer Support RAG Security Demonstration Environment

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "========================================================================"
echo " Starting Customer Support RAG AI Security Demonstration Environment"
echo " OWASP LLM06 (Excessive Agency) & LLM04 (Unbounded Consumption)"
echo "========================================================================"

# Check Python version
python3 --version

# Run automated tests first to verify integrity
echo -e "\n--> Verifying security test suite..."
python3 -m pytest -q

# Start FastAPI server with uvicorn
echo -e "\n--> Launching application server on http://localhost:8000 ..."
exec python3 -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
