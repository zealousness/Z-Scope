"""Read only already-generated native probe report errors, without execution."""
from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[5]))
from zscope.reporting.json_io import read_report

base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('/tmp/zscope-branch-check-78k0lsqc/pytest-of-zeal/pytest-0')
for project in sorted(base.glob('test_*')):
    report = project / 'report.json'
    if not report.is_file():
        continue
    value = read_report(report)
    print(json.dumps(dict(report=str(report), summary={key: value.get('summary', {}).get(key) for key in ('functions_completed', 'functions_failed')}, functions=[{key: item.get(key) for key in ('function', 'entry_key', 'error', 'verdict', 'duration_seconds')} for item in value.get('function_results', [])], metadata_keys=list(value.get('metadata', {})), entry_instances=value.get('metadata', {}).get('entry_instances')), ensure_ascii=False))
