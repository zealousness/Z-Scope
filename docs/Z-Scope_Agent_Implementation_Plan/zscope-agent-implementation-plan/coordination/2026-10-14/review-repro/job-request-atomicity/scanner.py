import sys
from pathlib import Path
from zscope.reporting.json_io import write_report_atomic
with Path(sys.argv[2]).open('a') as f: f.write('scanner\n')
write_report_atomic(Path(sys.argv[1])/'report.json', {'schema_version':2,'issues':[],'completeness':'complete','metadata':{'synthetic_only':True}})
