# Docker Linux Verification

This directory contains Docker-based verification for ZScope on Linux.

## Quick Start

### Windows PowerShell

```powershell
# Basic verification (no LLM analysis)
.\run_verification.ps1 -Build

# Full verification with API key
.\run_verification.ps1 -ApiKey "your-openai-api-key"

# Clean up
.\run_verification.ps1 -Clean
```

### Direct Docker Commands

```bash
# Build image
docker-compose build

# Run verification
docker-compose run --rm zscope bash /app/verify_linux.sh

# Interactive shell
docker-compose run --rm zscope bash
```

## Files

- `Dockerfile` - Linux environment with Python 3.9 + clang/libclang
- `docker-compose.yml` - Container orchestration
- `verify_linux.sh` - Verification script (runs inside container)
- `run_verification.ps1` - Windows wrapper script
- `test_c_project/` - Sample C code with defects for testing
- `output/` - Generated reports and snapshots

## Environment Variables

Set these in your environment or via PowerShell parameters:

- `OPENAI_API_KEY` - API key for LLM
- `OPENAI_BASE_URL` - API endpoint (default: https://api.openai.com/v1)
- `OPENAI_MODEL` - Model name (default: gpt-4)
