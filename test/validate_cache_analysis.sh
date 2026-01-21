#!/bin/bash
# ZScope Cache Module Validation Script
# This script runs ZScope on the cache module and validates detection results

echo "======================================================================="
echo "ZScope Cache Module Defect Detection Validation"
echo "======================================================================="
echo ""

# Check if Ollama is accessible
echo "[1/4] Checking Ollama connectivity..."
python3 <<EOF
import requests
try:
    resp = requests.get("http://host.docker.internal:11434/v1/models", timeout=5)
    if resp.status_code == 200:
        print("  ✓ Ollama is accessible")  
        exit(0)
    else:
        print("  ✗ Ollama returned HTTP", resp.status_code)
        exit(1)
except Exception as e:
    print(f"  ✗ Cannot reach Ollama: {e}")
    exit(1)
EOF

if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Ollama is not accessible from Docker container"
    echo "Please ensure:"
    echo "  1. Ollama is running on host (port 11434)"
    echo "  2. docker-compose.yml has extra_hosts configured"
    exit 1
fi

echo ""
echo "[2/4] Verifying cache module files..."
cd /app/zscope/tests/cache_module || exit 1

REQUIRED_FILES=(
    "include/cache_manager.h"
    "src/cache_core.c"
    "src/cache_index.c" 
    "src/cache_queue.c"
    "src/cache_storage.c"
    "zscope.yaml"
    "compile_commands.json"
)

ALL_FOUND=true
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file"
    else
        echo "  ✗ $file NOT FOUND"
        ALL_FOUND=false
    fi
done

if [ "$ALL_FOUND" = false ]; then
    echo ""
    echo "ERROR: Missing required files"
    exit 1
fi

echo ""
echo "[3/4] Running ZScope analysis..."
echo "  Target: cache_get() function"
echo "  Backend: libclang + CCLS"
echo "  LLM: Ollama (Qwen3-30B)"
echo ""

# Run ZScope (this may take several minutes)
zscope --config zscope.yaml 2>&1 | tee /tmp/zscope_analysis.log

ANALYSIS_EXIT=$?

echo ""
echo "[4/4] Validating detection results..."

# Check if analysis completed
if [ $ANALYSIS_EXIT -ne 0 ]; then
    echo "  ⚠ ZScope exited with code $ANALYSIS_EXIT"
else
    echo "  ✓ ZScope analysis completed"
fi

# Look for generated reports
if [ -d ".zscope_snapshots_cache" ] || [ -f "analysis_report.json" ] || [ -f "*.md" ]; then
    echo "  ✓ Output files generated"
else
    echo "  ⚠ No output files found"
fi

# Check log for key indicators
echo ""
echo "Analysis Summary from Log:"
echo "-----------------------------------"

if grep -q "buffer" /tmp/zscope_analysis.log; then
    echo "  ✓ Mentioned: buffer (DEFECT #2 related)"
fi

if grep -q "leak\|free\|memory" /tmp/zscope_analysis.log; then
    echo "  ✓ Mentioned: memory/leak (DEFECT #3 related)"
fi

if grep -q "file\|descriptor\|fd\|close" /tmp/zscope_analysis.log; then
    echo "  ✓ Mentioned: file/fd (DEFECT #4 related)"  
fi

if grep -q "overflow\|bounds\|index" /tmp/zscope_analysis.log; then
    echo "  ✓ Mentioned: overflow/bounds (DEFECT #2, #5 related)"
fi

echo ""
echo "======================================================================="
echo "Validation Complete"
echo "======================================================================="
echo ""
echo "Next steps:"
echo "  1. Review /tmp/zscope_analysis.log for full output"
echo "  2. Check generated reports in current directory"
echo "  3. Verify if all 6 defect types were detected"
echo ""
