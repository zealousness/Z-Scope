"""Prepare an expanded launcher; never run it before independently accepted intake."""
from pathlib import Path

HERE=Path(__file__).resolve().parent
source=(HERE/"verify_current_root.py").read_text(encoding="utf-8")
anchor="if BACKEND_ONLY:\n    TESTS ="
assert source.count(anchor)==1
tests=["tests/test_instance_analysis.py","tests/test_job_session_scheduler.py"]
tests += ["docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r6/"+name for name in (
    "test_instance_consumer_guard.py","test_instance_navigation_consumers.py","test_instance_validation_scope.py",
    "test_scheduler_guard_probes.py","test_scheduler_discovery_durability.py","test_scheduler_settlement_edges.py")]
import json
source=source.replace(anchor,"TESTS += "+json.dumps(tests,indent=4)+"\n"+anchor)
source=source.replace('    "zscope/config/editor.py", "zscope/cli/config_cli.py", "zscope/cli/init.py",\n    "zscope.c_cpp.yaml",',
                      '    "zscope/retrieval/instance_index.py", "zscope/core/analysis/analyzer.py",\n    "zscope/orchestration/parallel_analyzer.py",\n    "zscope/config/editor.py", "zscope/cli/config_cli.py", "zscope/cli/init.py",\n    "zscope.c_cpp.yaml",')
anchor='    "tests/test_cli_config_v2.py", "tests/test_reference_configs.py",\n]'
assert source.count(anchor)==1
source=source.replace(anchor,'    "tests/test_cli_config_v2.py", "tests/test_reference_configs.py",\n    "zscope/retrieval/instance_index.py", "tests/test_instance_analysis.py",\n    "tests/test_job_session_scheduler.py",\n]')
source=source.replace('S01/S08 R1 consumers not intaken and JOB04/JOB06/full instance analysis pending.',
                      'Includes intaken S01 instance API/shared-validation native tests and S08 transactional queue/session consumer/owner tests; complete ScanSession scheduling and scanner work-queue wiring, JOB04/JOB06/full consumer migration remain pending.')
target=HERE/"verify_current_root_r9.py"
assert not target.exists()
target.write_text(source,encoding="utf-8",newline="\n")
print("Prepared R9 launcher: original34 + 2 delivered suites + 6 coordinator probe files, same6 quality commands and default fd capture. Root product bytes untouched.")
