import time
import sys
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "zscope"))

from zscope.config.config import ZScopeConfig, AnalysisConfig, ProjectConfig, LLMConfig
from zscope.core.parallel_analyzer import ParallelAnalyzer
from zscope.config.function_entry import FunctionEntry

# Setup basic logging to stdout
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Create a mock config with 3 workers
config = ZScopeConfig(
    llm=LLMConfig(api_key="123", base_url="mock", provider="openai"),
    llms={},
    indexing=None,
    project=ProjectConfig(project_root=Path("."), source_root=Path(".")),
    analysis=AnalysisConfig(parallel_workers=3, snapshot_dir=".mock")
)

# Subclass to prove the behavior
class MockParallelAnalyzer(ParallelAnalyzer):
    def __init__(self, config):
        self.max_workers = config.analysis.parallel_workers

    def _analyze_single_entry(self, entry: FunctionEntry):
        print(f"-> Worker Thread started for function: {entry.function_name}")
        # Simulate long semantic modeling
        time.sleep(2)  
        print(f"   {entry.function_name} finished semantic modeling.")
        # Simulate long vulnerability analysis
        time.sleep(2)
        print(f"<- Worker Thread finished function: {entry.function_name}")
        class MockResult:
            verdict = "no_issues"
            issues = []
        return MockResult()

print("Launching analyzer with 3 parallel workers...\n")
entries = [FunctionEntry(f"func_{i}") for i in range(1, 6)]
analyzer = MockParallelAnalyzer(config)
analyzer.analyze_function_entries(entries)
print("\nDone proof!")
