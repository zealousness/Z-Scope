#!/bin/bash
# Scan ALL public API functions without hints

cd /app/zscope/tests/cache_module

# All 10 public API functions from cache_manager.h
FUNCTIONS=(
    "cache_create"
    "cache_put"
    "cache_get"
    "cache_delete"
    "cache_get_stats"
    "cache_list_entries"
    "cache_save"
    "cache_load"
    "cache_clear"
    "cache_destroy"
)

echo "=========================================="
echo "ZScope Comprehensive Blind Scan"
echo "Target: All 10 Public API Functions"
echo "Mode: No defect hints provided"
echo "=========================================="
echo ""

TOTAL_ISSUES=0
RESULTS_FILE="/tmp/all_findings.json"

# Initialize results
echo "{\"scans\": [" > $RESULTS_FILE

for i in "${!FUNCTIONS[@]}"; do
    FUNC="${FUNCTIONS[$i]}"
    echo "[$((i+1))/10] Analyzing: $FUNC"
    echo "----------------------------------------"
    
    # Replace PLACEHOLDER with actual function
    sed "s/entry_function: PLACEHOLDER/entry_function: $FUNC/" zscope_blind.yaml > /tmp/config_$FUNC.yaml
    
    # Run analysis
    zscope --config /tmp/config_$FUNC.yaml 2>&1 | grep -E "Verdict|Issues found" || true
    
    # Collect report
    if [ -f "report.json" ]; then
        ISSUES=$(jq '.issues | length' report.json 2>/dev/null || echo "0")
        VERDICT=$(jq -r '.overall_verdict' report.json 2>/dev/null || echo "unknown")
        
        echo "  Result: $VERDICT, Issues: $ISSUES"
        TOTAL_ISSUES=$((TOTAL_ISSUES + ISSUES))
        
        # Add to combined results
        if [ $i -gt 0 ]; then
            echo "," >> $RESULTS_FILE
        fi
        echo "{\"function\": \"$FUNC\", \"verdict\": \"$VERDICT\", \"issues\":" >> $RESULTS_FILE
        jq '.issues' report.json >> $RESULTS_FILE
        echo "}" >> $RESULTS_FILE
        
        # Save individual report
        cp report.json /tmp/report_$FUNC.json
        cp report.md /tmp/report_$FUNC.md
    else
        echo "  ERROR: No report generated"
    fi
    
    echo ""
done

echo "]}" >> $RESULTS_FILE

echo "=========================================="
echo "SCAN COMPLETE"
echo "=========================================="
echo "Total Issues Found: $TOTAL_ISSUES"
echo ""
echo "=== COMBINED FINDINGS ==="
cat $RESULTS_FILE | jq .

# Show summary
echo ""
echo "=== SUMMARY BY FUNCTION ==="
cat $RESULTS_FILE | jq -r '.scans[] | "\(.function): \(.verdict) (\(.issues | length) issues)"'
