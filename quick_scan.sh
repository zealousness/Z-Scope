#!/bin/bash
# Quick scan of key functions with immediate output

cd /app/zscope/tests/cache_module

# Key functions that should contain our 6 defects
FUNCTIONS=(
    "cache_get"      # DEFECT #2: buffer overflow
    "cache_clear"    # DEFECT #5: untrusted index, #6: memory accumulation  
    "cache_save"     # DEFECT #4: FD leak
)

for FUNC in "${FUNCTIONS[@]}"; do
    echo "========================================"
    echo "Function: $FUNC"
    echo "========================================"
    
    sed "s/entry_function: PLACEHOLDER/entry_function: $FUNC/" zscope_blind.yaml > /tmp/config.yaml
    
    zscope --config /tmp/config.yaml 2>&1 | grep -E "INFO|WARNING|Verdict|Issues" | tail -20
    
    if [ -f "report.json" ]; then
        echo ""
        echo "--- DETECTED ISSUES ---"
        cat report.json | grep -A 100 '"issues"' | head -80
        echo ""
    fi
done
