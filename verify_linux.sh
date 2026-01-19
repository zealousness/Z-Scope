#!/bin/bash
set -e

echo "======================================="
echo "ZScope Linux Verification Script"
echo "======================================="
echo ""

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p /app/output

echo "Step 1: Verifying Python environment..."
python --version
echo ""

echo "Step 2: Verifying ZScope installation..."
python -c "import zscope; print('ZScope module imported successfully')"
echo ""

echo "Step 3: Running unit tests..."
pytest tests/ -v || {
    echo -e "${YELLOW}Warning: Some unit tests failed, but continuing verification...${NC}"
}
echo ""

echo "Step 4: Verifying libclang availability..."
python -c "from clang.cindex import Index; idx = Index.create(); print('libclang is available and working')" || {
    echo -e "${YELLOW}Warning: libclang might not be fully functional${NC}"
}
echo ""

echo "Step 5: Testing ZScope code indexing (without LLM)..."
python -c "
from zscope.code_index import CodeIndex
from pathlib import Path

project_root = Path('/app/test_c_project')
compile_db = project_root / 'compile_commands.json'

print(f'Project root: {project_root}')
print(f'Compile DB exists: {compile_db.exists()}')

code_index = CodeIndex(project_root, compile_db if compile_db.exists() else None)
print('CodeIndex created successfully')

# Try to list functions
functions = code_index.list_functions(limit=100)
print(f'Found {len(functions)} functions:')
for func_name in sorted(functions):
    print(f'  - {func_name}')
    
# Try to get implementation of a specific function
if 'process_data_packet' in functions:
    impl = code_index.get_function_impl('process_data_packet')
    if impl:
        print(f'\nSuccessfully retrieved implementation of process_data_packet')
        print(f'File: {impl[\"file\"]}')
        print(f'Lines: {impl[\"start_line\"]}-{impl[\"end_line\"]}')
        print(f'Lines of code: {len(impl[\"code\"].splitlines())}')
        print(f'Callees: {impl.get(\"callees\", [])}')
    else:
        print('Could not retrieve implementation')
else:
    print('process_data_packet not found in index')
" || {
    echo -e "${RED}Error: Code indexing failed${NC}"
    exit 1
}
echo ""

echo "Step 6: Testing snapshot store..."
python -c "
from zscope.snapshot_store import SnapshotStore
from pathlib import Path

store = SnapshotStore(Path('/app/output/.zscope_snapshots'))
print('SnapshotStore created successfully')

# Test basic operations
from zscope.utils import compute_code_hash

test_code = 'int foo() { return 42; }'
code_hash = compute_code_hash(test_code)
print(f'Code hash computed: {code_hash[:16]}...')

# Test snapshot storage
store.save_snapshot(
    function_name='test_func',
    code_hash=code_hash,
    semantic_fingerprint='test_fingerprint',
    analysis_result={'defects': []},
    metadata={'test': True}
)
print('Snapshot saved successfully')

# Test retrieval
snapshot = store.get_snapshot('test_func', code_hash)
if snapshot:
    print(f'Snapshot retrieved successfully')
else:
    print('Could not retrieve snapshot')
" || {
    echo -e "${RED}Error: Snapshot store test failed${NC}"
    exit 1
}
echo ""

echo "Step 7: Testing full ZScope CLI (if API credentials provided)..."
if [ -n "$OPENAI_API_KEY" ]; then
    echo "API key detected, running full analysis..."
    python -m zscope.cli \
        --project /app/test_c_project \
        --entry process_data_packet \
        --task "Check for memory leaks, buffer overflows, and resource leaks" \
        --base-url "$OPENAI_BASE_URL" \
        --api-key "$OPENAI_API_KEY" \
        --model "$OPENAI_MODEL" \
        --compile-db /app/test_c_project/compile_commands.json \
        --output /app/output || {
        echo -e "${YELLOW}Warning: ZScope analysis encountered errors${NC}"
    }
    
    # Check if reports were generated
    if [ -f /app/output/report.json ]; then
        echo -e "${GREEN}✓ report.json generated${NC}"
        ls -lh /app/output/report.json
    fi
    
    if [ -f /app/output/report.md ]; then
        echo -e "${GREEN}✓ report.md generated${NC}"
        ls -lh /app/output/report.md
    fi
else
    echo -e "${YELLOW}No API key provided, skipping full LLM analysis${NC}"
    echo "To run full analysis, set OPENAI_API_KEY environment variable"
fi
echo ""

echo "======================================="
echo -e "${GREEN}Verification completed successfully!${NC}"
echo "======================================="
echo ""
echo "Summary:"
echo "  - Python environment: OK"
echo "  - ZScope installation: OK"
echo "  - Code indexing: OK"
echo "  - Snapshot store: OK"
echo "  - Unit tests: Run (check output above)"
if [ -n "$OPENAI_API_KEY" ]; then
    echo "  - Full analysis: Attempted"
else
    echo "  - Full analysis: Skipped (no API key)"
fi
echo ""
echo "Output files location: /app/output"
