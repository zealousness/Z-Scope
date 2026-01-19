#!/bin/bash
# Run ZScope and save reports to host

cd /app/zscope/tests/cache_module

echo "Running ZScope analysis..."
zscope --config zscope_simple.yaml

echo ""
echo "=========================================="
echo "ANALYSIS COMPLETE"
echo "=========================================="
echo ""

if [ -f "report.json" ]; then
    echo "=== REPORT JSON ==="
    cat report.json
    echo ""
    echo ""
    echo "=== REPORT MARKDOWN ==="
    cat report.md
else
    echo "ERROR: No report files generated"
    exit 1
fi
