# Z-SCOPE

**Z-SCOPE** is an AI-powered static analysis tool for C projects. It uses Large Language Models (LLMs) to perform deep semantic analysis of code, looking for real defects like resource leaks, concurrency issues, and logic bugs, while ignoring stylistic complaints.

## Features

- **Semantic Analysis**: Goes beyond regex or standard static analysis AST checks. Uses LLM to understand intent.
- **Incremental Analysis**: Caches "semantic snapshots" of functions. If code changes but semantics don't (e.g., rename variable), it skips re-analysis.
- **Tool-Assisted**: The LLM can request to see callee functions to trace logic across boundaries.
- **Structured Reporting**: Outputs JSON and Markdown reports with confidence scores and impact levels.

## Installation

Requires Python 3.9+.

```bash
# Clone the repository
git clone https://github.com/yourusername/zscope.git
cd zscope

# Install dependencies
pip install -e .
```

## Usage

### Prerequisites
1. **Compile Commands**: For best results, generate a `compile_commands.json` for your C project (e.g., using CMake `set(CMAKE_EXPORT_COMPILE_COMMANDS ON)`). If not available, Z-SCOPE acts in "best-effort" regex mode.
2. **LLM Access**: You need access to an OpenAI-compatible API (e.g., OpenAI, Azure OpenAI, vLLM, text-generation-webui).

### Running Analysis

```bash
python -m zscope.cli \
  --project /path/to/my/c_project \
  --entry "process_data_packet" \
  --task "Check for buffer overflows and memory leaks in packet handling logic." \
  --base-url "https://api.openai.com/v1" \
  --api-key "sk-..." \
  --model "gpt-4"
```

### Arguments

- `--project / -p`: Absolute path to the root of your C project.
- `--entry / -e`: Name of the C function to start analyzing.
- `--task / -t`: Natural language description of what you want to check.
- `--base-url`: URL of the LLM API.
- `--api-key`: API Key for authentication.
- `--compile-db`: (Optional) Path to `compile_commands.json`.

## Output

After running, Z-SCOPE creates:
- `report.json`: Machine-readable full report.
- `report.md`: Human-readable summary.
- `.zscope_snapshots/`: Directory containing cached function semantics.

## Architecture

- **Code Index**: Locates function definitions using libclang or regex.
- **Snapshot Store**: SQLite-backed storage for function semantic fingerprints.
- **Tool Runtime**: Exposes tools (`get_function_impl`, `get_function_snapshot`) to the LLM.
- **Analyzer**: Orchestrates the agentic loop.
