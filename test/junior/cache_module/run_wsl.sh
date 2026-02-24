#!/bin/bash
export NO_PROXY="*"
export no_proxy="*"
export PYTHONPATH="/mnt/c/Users/10273/home/work/Z-Scope/zscope"

echo "Activating venv and running Z-Scope..."
source venv/bin/activate

python3 -c "import sys; from zscope.cli.cli import main; sys.argv=['zscope', '-c', 'zscope.yaml', '--mode', 'topdown', '--verbose']; main()"
