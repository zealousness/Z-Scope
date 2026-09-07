# Z-SCOPE v1.3.2

**Z-SCOPE** 是一款基于 **多智能体（Multi-Agent）** 协作的 C/C++ 静态分析平台，并提供 Java Preview。它把可插拔代码索引、确定性规则、结构/值流后端信号、项目语义配置、人工反馈记忆与大语言模型（LLM）验证结合起来，模拟资深安全研究员的审计过程。

v1.3.2 在 v1.3.1 稳定线之上引入 LLM Wiki 项目知识层、自适应语义发现与 Validator v3 分层验证，落地 public config v2 与跨语言规则治理，交付 Linux Portable 四包离线发布，并对 Clang 索引与 SVF 值流链路做系统性性能优化。包内 `1.3.2` 是版本唯一真源，发布标签必须为 `v1.3.2`；`zscope.candidate.v3.3` 等字符串仅代表内部数据协议，不是产品版本。详见 [v1.3.2 发布说明](docs/releases/v1.3.2.md)。

## 核心特性

- **多智能体协作与声明式编排**：`AGENT.md` 与 `SKILL.md` 契约定义语义建模、漏洞扫描、验证、Issue Reconciler、Wiki Compiler 及聚焦型 Deep Worker 等智能体与技能，`zscope/workflows/*.yaml` 与 `WorkflowRunner` 驱动实际执行步骤。函数源码、调用图、污点追踪、指针别名等 14 个内置工具由 `ToolPolicy` 统一做参数校验、敏感路径拦截与审计日志。
- **自适应语义发现与分层验证**：确定性/backend 候选走低成本快车道；balanced/deep 额外构建 Security Semantic Map，并用 candidate-blind coverage-gap worker 主动提出 hypothesis。所有来源统一进入全局 Candidate Ledger，再由 V0 确定性 proof、V1 单次结构化判定、V2 定向补证复判和高风险 V3 短调查闭合。
- **LLM Wiki 项目知识层**：扫描 workflow 在入口分析前执行一次 session 级 `wiki_compile`，把项目内说明性 Markdown 确定性分类、按 heading 切分为稳定 source section，并以不可变 revision 发布 Wiki 知识。批量入口、Validator、Web 与 MCP 共享同一个只读 `ProjectKnowledgeService`；Compiler 不可用或 Wiki 损坏时回退带路径、标题、行号与 digest 的原文摘录查询。`project.wiki.mode` 默认 `off`，`zscope-wiki` CLI 提供独立的状态、查询与维护入口。详见 [LLM Wiki](docs/modules/wiki.md)。
- **证据优先的候选流水线**：`CandidatePipeline` 汇总本地规则、Clang AST/CFG、SVF/Saber、跨函数图候选与 KnowledgeDB/Joern 后端信号，覆盖 fd 表示契约、raw/encoded fd 混用、EAGAIN/EINTR 无预算重试、协议元素数与字节数错配、宏锁编译为空、部分资源初始化失败回滚等模式。后端按语言隔离：C/C++ 默认 `unified`，Java 默认 `java_unified`；弱后端必须显式选择，深度后端失败不会自动降级。
- **跨语言规则治理**：Java 与 C/C++ 内置确定性检测器、YAML pack 和 Python provider 共用严格规则目录、canonical ID、Skill 校验与 `EffectiveRuleSet`；SVF/Saber、Joern 等仍保持 backend signal 身份，禁用规则不影响后端信号与 LLM 独立发现。
- **验证组终态与有界 Validator 协议**：`CandidateEnvelope v3.3`、`SecurityObligation` 和 scan-level validation group 保证每个安全义务只验证一次，并闭合为 `confirmed`、`rejected_with_proof`、`needs_review`、`engine_failed` 或 `interrupted`；只有完整、可追溯且无冲突的 proof 能改变安全终态，引擎故障不会伪装成漏洞。每个 cluster 只传 bounded `ValidatorEvidenceSlice v3`：V1 是无工具、严格 schema 的单次判定，V2 按义务一次补齐事实后单次复判，V3 是最长 50 次模型迭代、仅白名单只读工具的有界调查，可引用事实完全闭合后才进入默认视图。
- **稳定缺陷身份与 Canonical 报告**：`canonical_issue_key`、`stable_issue_fingerprint` 等统一身份服务去重、baseline、SARIF partial fingerprints 与 benchmark 匹配。`ReportAssembler` 只从冻结的 canonical outcome 集合生成默认视图和含复核视图；`FindingRoot v1` 仅合并 defect family、结构化 subject、decision region、代码与 proof 上下文完全等价的义务。CLI 支持 `--export-sarif` 输出 SARIF v2.1.0，Web 端可导出自包含 HTML 审计报告。
- **运行模式与增量分析**：支持全新扫描（默认）、断点续扫（`--resume`）、增量维护（`--maintain`）与告警验证（`--mode alert-verify`）；diff impact 扫描（`--diff-base/--diff-head`）按变更意图选择最小必要扫描 root，并区分增量/存量发现。`--discover-entries` 自动识别头文件暴露的公共 API、网络收发、线程入口与用户输入点作为批量入口。
- **用户配置与反馈记忆**：`user_config.xlsx` 维护外部函数描述、配对函数、函数指针指向、dispatcher 分支、模块生命周期与函数意图；`--infer-user-config` 从源码、函数式宏与语义快照生成候选行供人工审阅（LLM 逐行筛选，低置信度行二轮复核），运行时只注入当前函数真正引用到的配置。Web 复核状态持久化为误报抑制与 finding baseline，经 `ReviewMemory` 在后续扫描自动复用；分析结果与证据 IR 落入 `.zscope_snapshots/` 与 `code_knowledge.db`。
- **多入口与多模型接入**：提供 CLI、Alpine.js + DaisyUI Web 仪表盘（审计发现、规则目录、项目配置、用户配置与看板）与 MCP Server（本地 stdio；实验性 Streamable HTTP 远程绑定需显式 bearer token 与客户端 allowlist）。LLM 支持多 profile 并按 modeling/analysis/validation 角色映射，同一 profile 可配置多个 `base_urls` 与 endpoint 限流分摊批量请求。

## 系统架构

```
CLI / Web / MCP / SARIF 入口层
    │
    ├─→ 默认/批量模式 (WorkflowRunner + Analyzer)
    ├─→ 规则驱动兼容模式 --mode ruledriven（C/C++ 在 1.x 弃用，2.0 删除）
    ├─→ 告警验证模式 --mode alert-verify
    ├─→ SARIF 标准导出 --export-sarif
    ├─→ 自动入口发现 --discover-entries
    ├─→ Diff impact 扫描 --diff-base/--diff-head [--diff-repo-root] [--diff-path]
    ├─→ 用户配置工作簿推断 --infer-user-config
    └─→ MCP 服务 --mcp-stdio / --mcp-http
          │
          ▼
声明式工作流编排 (workflows/ + SpecRegistry)
          │
          ▼
CodeIndex (可插拔后端 + per-run cache) + SnapshotStore + UserConfigStore(XLSX + state DB) + KnowledgeDB IR
          │
          ├─ CodeBackend ABC (backend_base.py)
          │  ├─ JoernBackend    — Java 信号；C/C++ 仅保留 1.x 兼容入口
          │  ├─ ClangBackend    — clangd LSP 批量提取 → KnowledgeDB
          │  ├─ UnifiedBackend  — ClangBackend + SvfAnalyzer (entry cluster + bitcode pool)
          │  ├─ JavaSource/UnifiedBackend — Java source + SootUp/WALA/Joern signals
          │  └─ RegexBackend    — 正则回退
          │
          ├─→ LLM Wiki 编译 (wiki_compile, project.wiki) → ProjectKnowledgeService（session 级只读共享）
          ├─→ 确定性候选快车道 (CandidatePipeline)
          ├─→ Security Semantic Map → Coverage-gap Planner → candidate-blind hypotheses
          ├─→ 全局 CandidateLedger (跨入口去重 + freeze)
          ├─→ ScanTokenUsageLedger (逐调用计量，不参与运行时限流)
          ├─→ 工具总线 (ToolsRuntime + ToolPolicy) ── 外部 MCP 集成
          │
          ▼
分层验证 (agents/ + skills/)
V0 deterministic proof → V1 structured decision → V2 evidence delta recheck → V3 bounded investigation
          │
          ▼
ReviewMemory + ReportAssembler + 归因/预算审计 + SARIF 导出 + Web 反馈闭环
```

## 数据安全与审计留痕
Z-Scope 内置了多层防丢失和可追溯机制：
1. **快照级持久化**：语义快照与单函数最终报告会写入 `.zscope_snapshots/snapshots.db`，`--resume` 和 `--maintain` 都以该库作为跳过、复用和调和依据。
2. **热备份轮转**：在汇总合并最终的 `zscope_batch_report.json` 前，旧版本 JSON 会自动加盖时间戳并归档至 `.zscope_knowledge/backups/` 目录。
3. **证据 IR 与索引留痕**：确定性规则与后端信号产生的候选会将 source/sink、路径切片、资源/锁/共享状态事件写入 `code_knowledge.db` 的 IR 表；Clang 后端还会记录 macro 定义、翻译单元哈希和删除文件影响，便于复查和回归分析。
4. **人工反馈复用**：Web 仪表盘中的验证状态会持久化为 `finding_suppressions` 与 `finding_baselines`。`ReviewMemory` 会在验证、评分和报告前复用这些状态，后续扫描自动抑制已确认误报，并把历史反馈纳入评分。
5. **稳定身份、结构化根因与标准报告导出**：`candidate_uid`、`occurrence_uid`、`validation_cluster_uid`、`finding_root_uid` 和 `stable_issue_fingerprint` 分别服务候选、入口溯源、验证复用、报告投影与 baseline/SARIF。v1.3.2 报告保留 alias occurrence、入口路径、decision proof、affected subjects 和聚类遥测，便于复核每次确认、拒绝与合并。Web 前端可导出自包含 HTML 审计报告；CLI 可通过 `--export-sarif` 输出 SARIF v2.1.0。
6. **差异影响留痕**：diff impact 扫描会把 `base_ref`、`head_ref`、路径过滤器、变更函数、分析义务、覆盖摘要、fallback 原因和报告级 `diff_relevance` 写入结构化 JSON，避免把增量审计结论和存量问题混在一起。
7. **MCP 暴露面约束**：stdio MCP 默认本地使用；HTTP MCP 为实验性能力，远程 bind 需要 `--mcp-auth-token-env` 与 `--mcp-client-allowlist`，工具调用还会经过 `ToolPolicy`。
8. **模型与验证成本留痕**：LLM 客户端会记录累计 prompt/completion token、工具调用次数和 endpoint 等待信息；Validator fast-path、并行验证和告警验证也会把 token 与命中统计汇总进报告或 benchmark 成本指标。

## 依赖说明

### Python 依赖

Z-SCOPE 基于 Python 3.13 开发、测试和交付；源码安装要求 Python 3.13 及以上，离线/Portable 包内置 CPython 3.13，带哈希依赖约束位于 `requirements/constraints/py313.txt`。SQLite 运行库最低要求为 3.8.10.2，以实际解释器的 `sqlite3.sqlite_version` 为准；Python 版本本身不保证 Linux 上动态链接的 SQLite 版本。运行时依赖与外部运行库下限以 `pyproject.toml` 为准。

| 包名 | 用途 |
|------|------|
| `openai>=1.0.0` | LLM 客户端（OpenAI 兼容 API） |
| `requests>=2.31.0` | HTTP 请求 |
| `cpgqls-client>=0.0.5` | Java 可选依赖组中的 Joern CPGQL 客户端 |
| `click>=8.1.0` | CLI 框架 |
| `tqdm>=4.66.0` | 进度条 |
| `pyyaml>=6.0` | YAML 配置解析 |

开发依赖（可选）：`pytest`、`pytest-cov`、`black`、`mypy`、`types-PyYAML`、`types-requests`。

质量门禁固定使用 `mypy==1.19.1` 与 `black==25.11.0`，两者目标均为 Python 3.13；存量质量债务采用不可扩张基线管理。

### 外部工具依赖（按后端）

| 后端 | 必需工具 | 说明 |
|------|---------|------|
| `regex` | 无 | 纯正则，零外部依赖 |
| `joern` | Joern CLI + JDK 21 | Java 信号提供器；C/C++ 仅保留 1.x 弃用兼容入口 |
| `clang` | clangd >= 20.1 + compile_commands.json | clangd LSP 符号提取，无需 `pip install libclang` |
| `unified` | clangd >= 20.1 + (可选) clang-18 + Go/gllvm + binutils/objcopy + SVF 3.2 + LLVM/llvm-link/llvm-nm | Clang AST + SVF 深度分析，SVF 不可用时优雅降级；clang-18 仅用于 SVF/gllvm bitcode 链路，llvm-nm 用于入口裁剪后的符号闭包 |
| `java_source` / `java_unified` | Temurin 21、Maven、SootUp/WALA runner；默认信号还需 Joern | CodeQL 仅用户自备 |

## 安装指南

### 1. Linux Portable 解压即用（推荐）

按宿主架构（x86_64 / aarch64）与语言（cpp / java）选择一个独立 portable 包，并下载同次发布的校验和、签名、公钥和兼容性报告。包内已安装 Python 及对应分析工具：

```bash
openssl dgst -sha256 -verify public-key.pem -signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
tar -xzf zscope-1.3.2-linux-x86_64-cpp-portable.tar.gz
export PATH="$PWD/zscope-1.3.2-linux-x86_64-cpp-portable/bin:$PATH"
zscope-doctor --json-output
```

构建基线为 glibc 2.38，运行时使用宿主 glibc；符号需求下限和实际测试下限分别记录在逐包 ABI 与 smoke 报告中。C/C++ 包包含 clangd 22.1.7，以及独立的 LLVM 18/SVF 3.2 bitcode 链路；Java 包包含 JDK 21、Maven、预编译分析 JAR 和 Joern Java 功能，不包含 Gradle。两份语言模板不展示工具路径，代码仍保留手工实验覆盖。发布目录支持移动和只读挂载。完整布局、源码安装、旧分体安装器兼容与制作流程见 [离线安装与发布](docs/offline-installation.md)。Windows 用户通过 WSL2 使用 Linux 包。

### 2. 从源码安装

```bash
git clone https://github.com/zealousness/Z-Scope.git
cd Z-Scope
python -m pip install -e .

# Java Preview（包含 Joern Python 客户端；CodeQL 仍须用户自备）
python -m pip install -e ".[java]"

# 含开发依赖
python -m pip install -e ".[dev]"
```

优先从仓库根目录复制对应语言的参考配置：C/C++ 使用 [`zscope.c_cpp.yaml`](zscope.c_cpp.yaml)，Java 使用 [`zscope.java.yaml`](zscope.java.yaml)。也可以运行 `zscope-init --language c_cpp|java` 生成最小配置。准备好项目内的 `zscope.yaml` 后，运行 `zscope-doctor --profile auto --config zscope.yaml` 检查环境。

### 3. 安装后端依赖（按需选择）

**Regex 后端**（零依赖，开箱即用）：无需额外安装。

**Java Joern 信号提供器**（C/C++ Joern 已弃用）：

```bash
# 下载 Joern CLI（需要 JDK 21）
curl -L https://github.com/joernio/joern/releases/latest/download/joern-install.sh | bash

# 或手动下载解压到 dependency/joern/
# 验证
joern --version
```

**Clang 后端**：

```bash
# 1. 安装 clangd（用于 LSP 符号提取）
#    方法 A: 系统包（如果发行版提供 clangd >= 20.1）
sudo apt install clangd-20
#    方法 B: 独立二进制（无需 root）
mkdir -p ~/.local/clangd && cd ~/.local/clangd
curl -sL https://github.com/clangd/clangd/releases/download/22.1.0/clangd-linux-22.1.0.zip -o clangd.zip
unzip clangd.zip
# 然后在 zscope.yaml 的 indexing.tools.clangd 中配置路径

# 2. 生成 compile_commands.json（Clang 后端必须）
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
# 或使用 bear: bear -- make
```

> **注意**: Clang 后端使用 clangd LSP 进行符号提取和调用图构建，不需要 `pip install libclang`。建议使用 clangd >= 20.1；配置后端不可用或索引为空时会明确失败。

**Unified 后端**（Clang + SVF，完整安装）：

Unified 模式 = Clang AST 提取 + SVF 深度分析，两部分都是该后端契约的一部分。缺少 SVF/gllvm/LLVM 工具链时请显式改用 `clang` 或 `regex`，系统不会代替用户降级。

```bash
# ═══ 必需：Clang AST 提取 ═══

# 1. clangd（同 Clang 后端，建议 >= 20.1）
sudo apt install clangd-20

# 2. compile_commands.json
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..

# ═══ Unified 必需：SVF 深度分析 ═══

# 3. 安装 Clang 编译器（仅 SVF/gllvm bitcode 链路需要；需与 SVF 预编译包匹配）
sudo apt install clang-18

# 4. 安装 LLVM 工具链（llvm-link）
sudo apt install llvm

# 5. 安装 binutils（objcopy，gclang 嵌入 bitcode 需要）
sudo apt install binutils

# 6. 安装 Go（gllvm 依赖）
sudo apt install golang

# 7. 安装 gllvm（LLVM bitcode 提取：gclang, get-bc）
go install github.com/SRI-CSL/gllvm/cmd/...@latest
# 确保 ~/go/bin 在 PATH 中

# 8. 安装 SVF（指针分析 + 内存缺陷检测）
#    从 GitHub Release 下载预编译包：
curl -sL -o svf.zip \
  https://github.com/SVF-tools/SVF/releases/download/SVF-3.2/SVF-3.2-ubuntu-24.04-x86_64.zip
unzip svf.zip -d ~/.local/svf/
#    SVF 还需要配套的 LLVM 共享库：
curl -sL -o llvm.tar.gz \
  https://github.com/SVF-tools/SVF/releases/download/SVF-3.2/llvm-18.1.0-ubuntu20-rtti-x86-64.tar.gz
tar xzf llvm.tar.gz -C ~/.local/svf/
```

**环境变量**（SVF 所需，建议加入 `~/.bashrc`）：

```bash
export PATH="$HOME/go/bin:/usr/lib/llvm-18/bin:$HOME/.local/svf/SVF-linux-x86_64/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/svf/SVF-linux-x86_64/lib:$HOME/.local/svf/llvm-18.1.0.obj/lib:${LD_LIBRARY_PATH:-}"
export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-18
```

`LD_LIBRARY_PATH` 中的 LLVM 目录必须与下载的 SVF 配套包一致。若 `svf_bin_dir` 已配置，Z-SCOPE 会尝试发现相邻的 `lib` 与 `llvm-*.obj/lib`；仅把 `wpa`/`saber` 加入 `PATH` 时仍应显式设置该变量。可用以下命令在真正执行扫描的 Linux/WSL 用户态验证：

```bash
for tool in clang clangd gclang get-bc llvm-link llvm-nm wpa saber; do
  command -v "$tool" || { echo "missing tool: $tool" >&2; exit 1; }
done
if ldd "$(command -v wpa)" | grep -q 'not found'; then
  ldd "$(command -v wpa)" >&2
  exit 1
fi
if ldd "$(command -v saber)" | grep -q 'not found'; then
  ldd "$(command -v saber)" >&2
  exit 1
fi
```

**C/C++ `zscope.yaml` 配置片段**（unified 模式；完整参考见 [`zscope.c_cpp.yaml`](zscope.c_cpp.yaml)）：

```yaml
indexing:
  backend: unified
  svf:
    scope: auto
    entry_depth: 4
    max_selected_tus: 200
    fallback: full
    always_include: []
    exclusive_pools: []
    shared_pools: []
    heap_limit_mb: 32768
    timeout_seconds: 1800
  tools:
    clangd: clangd
    svf_bin_dir: ~/.local/svf/SVF-linux-x86_64/bin
    gclang: gclang
    get_bc: get-bc
    llvm_link: llvm-link
```

> **WSL 用户注意**: SVF 的 bitcode 构建（gclang + objcopy）在 NTFS 挂载路径 (`/mnt/c/...`) 上可能失败，Z-SCOPE 会自动重定向到 Linux 原生临时目录。启用入口裁剪时，构建目录还会写入 `bitcode_scope_<group>.json`，记录本次 SVF 选择了哪些源码和 `.bc` 文件，便于复查。详见 `.agents/workflows/wsl-pitfalls.md`。

## 端到端使用指南

### Step 1：初始化、校验并预览入口

仓库根目录只提供两份语言隔离的参考配置：

| 参考文件 | 固定语言 | 默认后端 |
|---|---|---|
| [`zscope.c_cpp.yaml`](zscope.c_cpp.yaml) | `c_cpp` | `unified` |
| [`zscope.java.yaml`](zscope.java.yaml) | `java` | `java_unified` |

首次接入推荐让初始化器识别语言、构建系统和候选模块。TTY 中会确认模块、接口文件 glob、后端和并发；CI 中使用非交互模式：

```bash
cd /path/to/target-project

# 交互式
zscope-init --project-root . --output zscope.yaml

# CI / 自动化
zscope-init --project-root . --language c_cpp --no-interactive --output zscope.yaml
```

生成后在执行 Z-SCOPE 的同一用户态显式设置 `Z_SCOPE_LLM_BASE_URL`、`Z_SCOPE_LLM_MODEL` 和 `Z_SCOPE_API_KEY`。不要把真实密钥写入仓库配置或提交到 Git：

```bash
export Z_SCOPE_LLM_BASE_URL='https://provider.example/v1'
export Z_SCOPE_LLM_MODEL='your-model-id'
export Z_SCOPE_API_KEY='your-secret-from-a-secret-store'
```

然后依次执行：

```bash
zscope-config validate --config zscope.yaml
zscope-doctor --config zscope.yaml
zscope -c zscope.yaml --plan-entries
zscope -c zscope.yaml
```

`--plan-entries` 只构建配置后端的索引，输出入口候选并写入项目根目录的
`entry_functions.discovered.json`；它不会调用 LLM 或执行漏洞扫描。若
`unified` / `java_unified` 缺少配置要求的深度工具链，doctor 和实际索引都会明确失败，不会静默降级到 regex。

#### public config v2

运行时只接受 `config_version: 2`。顶层允许
`config_version`、`llms`、`project`、`scan`、`indexing`、
`concurrency` 和可选 `rules`；未知键、重复 YAML 键、错误类型、跨语言字段和未展开的必需环境变量都会报出完整字段路径。

最小公共结构如下；完整字段和注释以两份参考文件为准：

```yaml
config_version: 2

llms:
  default:
    base_urls: ["${Z_SCOPE_LLM_BASE_URL}"]
    models: ["${Z_SCOPE_LLM_MODEL}"]
    api_key: "${Z_SCOPE_API_KEY}"
    base_url_max_concurrent_requests: 4

project:
  language: c_cpp                 # 只能是 c_cpp 或 java
  root: .                         # 相对路径基于加载时的当前工作目录解析（CLI/Web/MCP 子进程继承同一 CWD）
  source_root: .
  compile_commands_path: build/compile_commands.json
  include_paths: []
  exclude_paths: [build, third_party]
  entry_discovery:
    enabled: true
    search_root: .                # 相对 source_root 的待扫模块（相对路径固定基于 source_root 解析）
    interface_files: ["include/**/*.h"] # 相对 search_root 的 POSIX glob
    max_entries: 200
    max_functions: 10000

scan:
  # fast | balanced | deep；当前省略时为 fast。Java 暂只允许 fast。
  depth: fast
  # 空串启用当前语言全部适用 Skill；非空文本仅指定审计重点。
  task: ""
  # 可选；未配置的角色使用 llms.default。
  llm_profiles:
    modeling: default
    analysis: default
    validation: default

indexing:
  backend: unified

concurrency:
  entry_workers: 4
  validator_workers: 2
  investigator_workers: 1
  evidence_completion_workers: 2
  index_workers: 4
  wiki_compiler_workers: 4        # 仅 project.wiki 启用时使用
  svf_workers: 2                  # 仅 C/C++
  llm_max_inflight: 4
```

并发字段必须是正整数。`llm_max_inflight` 是进程级上限，仍会与 LLM profile 的 endpoint 并发/速率上限共同生效。请按 CPU、内存、SVF 峰值和 LLM 配额主动校准。

CLI 的 `--scan-depth fast|balanced|deep` 可覆盖本次运行，优先级固定为 CLI > YAML > 打包默认。档位决定启用哪些分析阶段及其结构化工作量边界，但不会设置 scan-wide token 硬上限。C/C++ 在质量门禁完成前省略 depth 仍是 fast；Java 显式请求 balanced/deep 会直接报错，不会降级。2M/12M/30M 等 token 数只存在于 Range Benchmark policy 中，作为扫描完成后的成本验收线。

C/C++ 的 SVF 项目规划继续由用户决定：

```yaml
indexing:
  backend: unified
  svf:
    scope: auto                    # full | auto | entry
    entry_depth: 4
    max_selected_tus: 200
    fallback: full                 # full | skip
    groups_file: ""
    always_include: []
    exclusive_pools: []
    shared_pools: []
    heap_limit_mb: 32768
    timeout_seconds: 1800
  tools:                           # 可选；省略时从 PATH 查找
    clangd: clangd
    gclang: gclang
    get_bc: get-bc
    llvm_link: llvm-link
    svf_bin_dir: /path/to/svf/bin
```

pool 名称在 exclusive/shared 两类之间也必须唯一；每个 pool 的 `paths` 非空，
`shared_pools[].conflicts_with` 必须引用已声明的 exclusive pool。Java 配置不接受
SVF、clangd 或 compile database 字段，使用 `indexing.java` 声明结构前端、signals 和外部 provider 命令。

#### 配置迁移

产品运行时不读取 v1。旧配置必须显式迁移，迁移器会转换已知别名并列出删除项和需人工复核项；未知旧字段会失败，不会静默丢弃：

```bash
zscope-config migrate --input old-zscope.yaml --output zscope.yaml
zscope-config validate --config zscope.yaml
```

默认不会覆盖源文件或已存在的输出；确认替换输出时显式传 `--force`。
旧 `parallel_workers` 会迁移到入口/SVF 并发，`max_clangd_threads` 会迁移到索引并发，之后仍应按实际环境重新校准。

#### 内置 RuntimeSpec

Agent 拓扑、Agent 到 LLM 角色的映射、分析预算、缓存、报告策略和稳定算法路径由打包的
`zscope/config/runtime_defaults.yaml` 管理，不出现在用户 YAML 中。
`AGENT.md`、`SKILL.md` 和 workflow YAML 仍分别是 prompt、工具和流程契约。

开发调试可用严格覆盖文件；普通运行设置覆盖路径会直接报错：

```bash
export Z_SCOPE_DEVELOPER_MODE=1
export Z_SCOPE_RUNTIME_SPEC=/absolute/path/runtime.override.yaml
zscope -c zscope.yaml
```

有效 RuntimeSpec 的版本、来源路径和 SHA-256 会进入配置哈希、缓存身份和最终报告 metadata。
知识库、快照和默认 `user_config.xlsx` 路径均相对 `project.root` 解析；如需指定工作簿，可设置 `project.user_config_file`。

#### scan.task 语义

`scan.task: ""` 会启用当前语言全部适用的漏洞 Skill。非空文本只用于表达本次审计重点，
例如“只关注并发和锁顺序”；运行时会按任务收窄 Skill，但不会把一段内置的通用漏洞描述当作默认任务。

#### 规则目录与禁用

包内 `zscope/rules/builtin_catalog.yaml` 管理 Java/C/C++ 确定性规则的 canonical ID、engine、CWE、Skill、revision、状态与能力要求。检测算法仍是 Python，目录不需复制到用户 YAML。扫描会在构建索引、启动外部工具或调用 LLM 前验证目录、Skill、pack、provider 和禁用列表。

只在需要扩展或关闭确定性检测器时增加 public `rules`：

```yaml
rules:
  packs:
    - security-rules/acme.yaml
  providers:
    - acme_rules
  # 默认关闭的 experimental 规则可显式启用。
  enabled_ids: []
  disabled_ids:
    - clang_cfg_use_after_release
```

`disabled_ids` 统一覆盖 Java local、C/C++ Regex、Clang CFG/matcher、Graph、YAML pack 和 Python provider，并优先于 `enabled_ids`；同一 ID 同时出现在两表时以禁用为准。单表内重复、未知或跨语言 ID 会严格失败。新内置规则默认 experimental/default-disabled，只有当前 revision 通过 qualification 后才能 stable/default-enabled。禁用一条规则不会抑制 SVF/Saber、Joern/Java provider 后端信号，也不会阻止 LLM 独立发现同一问题。后端信号通过 `indexing` 关闭；已确认误报通过 finding suppression 管理。

```bash
# 查看当前配置的有效规则、来源与启停原因
zscope-rules list --config zscope.yaml
zscope-rules list --config zscope.yaml --language c_cpp --engine cpp_graph --json
zscope-rules show clang_cfg_use_after_release --config zscope.yaml

# 验证或运行 YAML pack 内的正反例
zscope-rules validate security-rules/acme.yaml
zscope-rules test security-rules/acme.yaml
```

`zscope-rules` 与 `zscope-config validate`、doctor、CLI、Web 和 MCP 共用同一套规则预检/序列化语义。规则目录、实现、禁用列表与扩展来源的 SHA-256 会进入配置、cache/Validator 身份和最终报告 provenance。扩展契约和开发测试见 [`docs/rule-development.md`](docs/rule-development.md)。

### Step 2：执行分析

运行入口由配置决定：未配置 `entry_functions_list` 且未启用 `project.entry_discovery.enabled` 时走单入口；配置了 `entry_functions_list`，或入口发现产生了候选时走批量入口。

```bash
# 单入口模式：从 entry_function 开始分析
zscope -c zscope.yaml --verbose

# 本轮启用 C/C++ balanced；token 只在扫描完成后计量
zscope -c zscope.yaml --scan-depth balanced

# --verbose 会把模型交互与工具调用录制到 .zscope_conversations/，
# 供事后审计 llm_client 与工具行为（事件字典与调优指南见
# new_docs/conversation_recorder_events.md）

# 批量扫描模式：从 entry_functions_list JSON 开始
zscope -c zscope.yaml

# 断点续扫：跳过已完成的函数，继续中断的批量扫描
zscope -c zscope.yaml --resume

# 增量维护：仅对代码有变化的函数重新检视，复用未变化函数的历史报告
# CLI 会自动选择 zscope/workflows/maintain.yaml
zscope -c zscope.yaml --maintain

# 强制自动发现入口点并扫描：基于启发式扫描项目网络收发、线程与 API 暴露点
# 发现结果会写入项目根目录 entry_functions_list.json
zscope -c zscope.yaml --discover-entries

# 差异影响扫描：根据 git diff 自动选择受影响入口
# 生成 entry_functions_diff.json，并在报告中标注增量/存量/影响待确认
zscope -c zscope.yaml --diff-base origin/main --diff-head HEAD
# 若 source_root 是仓库子目录，可显式指定 git worktree 根
zscope -c zscope.yaml --diff-base origin/main --diff-head HEAD --diff-repo-root /path/to/git/root
# 只规划 src/net 与 src/fs 下的变更；必要的扫描 root 仍可位于路径外
zscope -c zscope.yaml --diff-base origin/main --diff-head HEAD --diff-path src/net --diff-path src/fs

# 推断/刷新人工可审阅的用户配置工作簿，然后退出
zscope -c zscope.yaml --infer-user-config

# 作为本地 MCP Server 运行（配合 Claude Desktop 等 MCP 客户端使用）
zscope -c zscope.yaml --mcp-stdio

# 作为实验性 Streamable HTTP MCP Server 运行（远程绑定必须提供 token 与 allowlist）
export ZSCOPE_MCP_TOKEN="replace-me"
zscope -c zscope.yaml --mcp-http --mcp-host 127.0.0.1 --mcp-port 8765 \
  --mcp-auth-token-env ZSCOPE_MCP_TOKEN --mcp-client-allowlist 127.0.0.1

# 1.x 兼容入口；C/C++ 已弃用并告警，2.0 删除
zscope --mode ruledriven -c zscope.yaml

# 告警验证模式：导入外部工具的 SARIF 报告，LLM 二次确认
zscope --mode alert-verify --sarif cppcheck_results.sarif -c zscope.yaml

# 扫描完成后导出 SARIF v2.1.0
zscope -c zscope.yaml --export-sarif zscope-results.sarif

# 仅构建代码索引（预热，不执行分析）
zscope --build-index -c zscope.yaml
# --build-cpg 仅是 1.x 弃用别名，2.0 删除
```

### Step 3：查看分析结果

分析完成后会按运行模式在项目根目录生成：

| 文件 / 目录 | 说明 |
|------|------|
| `report.md` | 单入口模式的人类可读报告 |
| `report.json` | 单入口模式的结构化缺陷数据，包含 `issues[]`、`report_views` 与 metadata |
| `zscope_batch_report.md` | 批量模式的人类可读审计汇总报告 |
| `zscope_batch_report.json` | 批量模式的结构化缺陷数据（可供 CI 集成），包含 `issues[]`、`report_views`、严重度分组和批量统计；覆盖前会把旧 JSON 备份到 `.zscope_knowledge/backups/` |
| `zscope_alert_verify_report.json` | 告警验证模式的验证结果 |
| `zscope-results.sarif` | `--export-sarif` 指定路径上的 SARIF v2.1.0 导出结果 |
| `entry_functions_list.json` | `--discover-entries` 或 `project.entry_discovery.enabled` 生成的候选入口列表 |
| `entry_functions_diff.json` | `--diff-base` 生成的差异影响入口列表，包含 `diff_impact.path_filters`、`analysis_obligations`、`coverage_summary`、`function_coverage` 和每个入口的 `diff_focus` |
| `.zscope_snapshots/` | 语义快照缓存（加速重复扫描） |
| `.zscope_snapshots/security_map.db` | 只读 Security Semantic Map sidecar；与历史函数 snapshot 分离 |
| `.zscope_snapshots/security_semantic_map.json` | 本轮安全语义地图、coverage、unknown/conflict 与 audit unit 的只读导出（balanced/deep；实际目录取 `runtime.analysis.snapshot_dir`） |
| `.zscope_snapshots/user_config.xlsx` | `--infer-user-config` 生成的人工可审阅用户配置工作簿（含 README sheet） |
| `.zscope_snapshots/user_config.infer_report.md` | 推理报告：全部 resource/lock 推理行、需人工复核清单、工作簿告警与统计 |
| `.zscope_snapshots/user_config.state.db` | 配置告警、finding suppression 与 baseline 的旁路状态库（若 `project.user_config_file` 指向其他 workbook，则与该 workbook 同名） |
| `.zscope_knowledge/code_knowledge.db` | 代码索引、SVF/Saber 信号和候选证据 IR |
| `.zscope_knowledge/wiki/` | `project.wiki` 启用后的 Wiki revision 状态库与审计事件链（默认关闭；目录由 `project.wiki.state_dir` 决定） |
| `.zscope_bc/bitcode_scope_<group>.json` | SVF 入口裁剪计划，记录选中的源码、bitcode、可达函数、link variants、重复符号和回退原因；WSL/NTFS 场景可能重定向到 Linux 原生临时目录 |
| `.zscope_bc/entry_cluster_layout_<group>.json` / `bitcode_manifest.json` | SVF 入口聚类布局与 bitcode/link 缓存 manifest，用于复用未变化的聚类和构建产物 |

单函数最终报告的 `metadata` 会记录 effective scan depth、实际 consumed token、按 agent/stage 的 usage、finish reason、候选漏斗、发现/决策归因、Validator verdict transition、Security Semantic Map coverage、主动发现单元，以及现有 rule/candidate/diff/report-view 统计。`report_views.default` 只包含默认可报告问题，`report_views.with_needs_review` 会额外包含需要人工复核的观察项。没有确定性反证时，LLM 的 rejected 也只能成为 needs-review，不能被静默隐藏。

退出码由 `--exit-policy` 控制，默认 `review`：报告中存在确认缺陷或 needs-review 观察项时返回 `1`，`clean` 返回 `0`；`confirmed` 策略只对确认缺陷返回 `1`，`legacy` 沿用 issues 计数语义。阶段因超时、取消、工具失败等原因未完成时，结果仍会保存并标记 `completeness=partial`，CLI 返回 `2`；fast 中未请求的语义/主动发现阶段不会触发 partial。token 成本超出 Benchmark 预期不会截断产品扫描。

### Step 4：启动 Web 仪表盘（可选）

```bash
zscope --dashboard -c zscope.yaml
# 可选：zscope --dashboard -c zscope.yaml --dashboard-host 127.0.0.1 --dashboard-port 8000
```

Dashboard 的 `POST /api/scan` 可按请求传入 `scan_depth`，并以 `GET /api/scan/status?scan_id=...` 查询 effective depth、实际 token usage 与最终 completeness；服务拒绝任意命令、环境或输出路径字段。MCP 对应提供 `zscope.scan.run` / `zscope.scan.status`，以及只读的 `zscope://reports/latest` 与 `zscope://rules/effective`。

仪表盘提供五个主要页面：

- **审计发现**：查看缺陷列表、报告视图和 evidence，支持六种验证状态标记，并将 `rejected` 反馈持久化为误报抑制和 baseline
- **规则目录**：只读查看 canonical ID、CWE、engine、Skill、revision、来源、能力要求和当前启停原因，支持语言/engine/Skill/状态筛选
- **项目配置**：按 v2 schema 和语言编辑项目、入口发现、审计重点、后端与并发；SVF pool、Java provider 和工具路径位于高级配置
- **用户配置**：以 `user_config.xlsx` 为入口维护 resource、lock、dispatcher、module lifecycle、pointer targets 和 function intents，支持保存、导入与下载
- **看板**：展示验证状态分布、风险概览、配置告警和审计进度

## 分析工具清单（14 个内置 Agent 工具）

| # | 工具名 | 用途 | 有效数据来源 |
|---|--------|------|---------|
| 1 | `get_function_impl` | 获取函数完整源码 | 全部 |
| 2 | `get_function_info` | 获取函数身份、项目/外部 callee 与函数式宏定义等结构化元数据 | 全部 |
| 3 | `get_function_snapshot` | 语义缓存复用 | 全部 |
| 4 | `get_security_semantics` | 读取 Security Semantic Map 的有界只读投影 | balanced/deep 生成的 `security_map.db`（默认 fast 不生成） |
| 5 | `list_known_functions` | 函数发现（正则搜索） | 全部 |
| 6 | `get_file_snippet` | 读取指定行范围的上下文代码 | 全部 |
| 7 | `get_callers` | 调用者查询（漏洞可达性分析） | joern/clang/unified；regex 返回空结果 |
| 8 | `get_type_info` | 结构体/类型定义查询 | joern/clang/unified；regex 返回空结果 |
| 9 | `get_call_graph` | 调用图聚合（直接调用；unified 可合并 SVF 间接调用） | joern/unified |
| 10 | `get_data_flow` | 污点追踪 | joern/unified |
| 11 | `find_function_pointers` | 回调/钩子发现 | joern/unified |
| 12 | `query_pointer_alias` | 指针别名查询 | unified |
| 13 | `verify_taint_reachability` | SVF/Saber 内存缺陷查询 | unified |
| 14 | `get_deep_call_context` | 高聚合查询（调用者+被调用者+间接调用+污点缺陷） | unified |

Agent 工具可见性由 `AGENT.md` 与后端能力共同决定：`semantic_modeler` 与 `validator_agent` 主要使用基础工具（含 `get_function_info`），Validator 额外可读取 `get_security_semantics`；`vulnerability_analyzer` 与 `deep_worker` 再开放第 9-14 个高级查询，其中 SVF 特有结果只有 unified 后端会返回有效数据。MCP Server 会额外暴露 `query_knowledge`（只读查询 `code_knowledge.db`）、`discover_entries`（入口发现）、`run_scan`/`scan_status` 与 `wiki_status`/`wiki_query` 等工具，供外部 MCP 客户端交互式审计使用。MCP 侧还提供 `zscope.code.*`、`zscope.graph.*`、`zscope.knowledge.query`、`zscope.entries.discover` 等 namespaced aliases；无论 stdio 还是 HTTP 传输，工具调用都会经过 `ToolPolicy`。

## 用户辅助配置

静态分析工具存在能力边界，Z-SCOPE 支持用户通过 Web 仪表盘补充以下信息，分析时自动注入上下文：

| 配置类型 | 说明 | 示例 |
|----------|------|------|
| 外部库函数描述 | 无法获取实现的外部函数的内存/并发行为 | `pthread_mutex_lock` 的锁语义 |
| 自定义配对函数 | 用户实现的 malloc/free、lock/unlock 等配对 | `my_alloc` ↔ `my_free` |
| 函数指针指向 | 函数指针、ops 表或 hook slot 的具体目标函数 | `handler_ptr` → `handle_read` |
| Dispatcher 分支 | 消息分发入口、message type、handler 及其资源 acquire/release 关系 | `MSG_APPLY` → `handle_apply` |
| 模块生命周期 | init/finit 配对、全局容器、错误路径是否必须回滚 | `module_init` ↔ `module_finit` |
| 函数设计意图 | 函数对调用者的约束和并发关系 | "此函数不会被并发调用" |
| Finding 抑制 | 对已确认误报按函数、位置、类别或规则进行抑制 | `src/demo.c:42` 的 `double_free` |
| Finding baseline | 记录历史验证结论，影响后续评分与过滤 | `true_positive` / `false_positive` / `needs_review` |

这些信息可以通过 Web 仪表盘维护，也可以放在 `user_config.xlsx` 中人工编辑。`--infer-user-config` 会生成候选行供审阅，人工确认后的行会在后续扫描中作为项目语义参与确定性候选生成、上下文注入和评分。Web 仪表盘保存验证结果时会自动维护 `finding_suppressions` 与 `finding_baselines`；命中误报抑制或 `false_positive` baseline 的候选会被过滤，命中 `true_positive` 的历史项会提高评分中的历史反馈分。

## 后端对比

| 特性 | regex（C/C++） | joern（Java；C 仅 1.x 兼容） | clang（C/C++） | unified（C/C++） |
|------|-------|-------|-------|---------|
| 外部依赖 | 无 | JDK 21 + Joern | clangd >= 20.1；可选 Clang 批量工具 | Clang 批量工具/clangd + 配套 Clang/LLVM + SVF；包装器兼容路径使用 gllvm |
| 函数源码提取 | 正则匹配 | CPGQL 精确 | AST 精确 | AST 精确 |
| 调用图 | 不支持 | 完整 CPG | 直接调用 | 直接 + 间接（SVF 指针分析） |
| 类型查询 | 不支持 | 完整 | AST 精确 | AST 精确 |
| 污点分析 | 不支持 | 数据流追踪 | 不支持 | SVF saber（内存泄漏/UAF/双重释放） |
| 间接调用解析 | 不支持 | 有限 | 不支持 | SVF Andersen 指针分析 |
| SVF bitcode 裁剪 | 不适用 | 不适用 | 不适用 | 支持按入口调用图、入口聚类、always include、互斥/共享 pool 和符号闭包裁剪，必要时回退 full/skip |
| 候选/信号入报告链路 | Regex 确定性候选进入 `CandidatePipeline` | Java local 规则是确定性候选；Joern 原生结果标记为 backend signal | Clang CFG/matcher 确定性候选与 KnowledgeDB 信号分类进入 | 确定性规则与 SVF/Saber/KnowledgeDB backend signal 分类进入证据 IR |
| 规则目录/禁用 | Regex 规则受 `disabled_ids` 控制 | Java local 受控；Joern signal 不受控 | Clang CFG/matcher 与 Graph 规则受控 | 确定性规则受控；SVF/Saber 信号不受控 |
| 内存占用 | 极低 | 高（JVM） | 中 | 中高 |

大项目可安装独立的 `zscope-clang-indexer`，通过 `indexing.clang.frontend: auto|batch|lsp` 切换批量抽取与 clangd 回退。普通 bitcode 编译可直接使用与 SVF 配套的 Clang；覆盖盘点、资源预算、安装与测量命令见 [Clang 批量索引与 SVF 输入验收](docs/clang-batch-indexing.md)。

## 开发命令

测试与质量命令一律在 Linux 环境执行；Windows 上必须在 WSL Linux 用户态中运行，并在 WSL 虚拟环境中完成安装（`python3 -m pip install -e ".[dev]"`）。不要用原生 Windows 解释器形成测试结论：解释器版本可能低于 3.13 基线，部分测试还依赖 POSIX 路径与文件语义。

```bash
# 安装开发依赖
python -m pip install -e ".[dev]"

# 格式化
black zscope/ --line-length 100

# 严格类型检查
python -m mypy zscope

# 强制编译检查，覆盖 Python 解释执行前可能隐藏的分支语法/导入问题
python -m compileall -f -q zscope scripts test tests

# 运行测试
python -m pytest

# 存量质量基线校验（mypy/Black 债务只允许缩小；--update 收敛需人工审查）
python scripts/check_mypy_baseline.py
python scripts/check_black_baseline.py

# 密钥历史审计（处理单分支用 --ref HEAD；全引用审计不带 --ref）
python scripts/scan_git_history_secrets.py --current-only

# Benchmark 仓库卫生与 clean-clone 离线 smoke（不调用 LLM）
python scripts/check_benchmark_hygiene.py
zscope-benchmark run --language c_cpp --mode smoke
zscope-benchmark run --language java --mode smoke

# 正式运行至少五轮；C/C++ 在 Windows 上自动转入 WSL
zscope-benchmark run --language c_cpp --mode formal --runs 5

# 外部 benchmark 协议：新结果输出 zscope.benchmark.v4，formal 聚合为 zscope.formal-benchmark.v3
python scripts/external_benchmark.py run-prepared --suite-root benchmarks/external/workspace/<suite> --condition candidate_layer --run-kind smoke
```

## 更新日志

### v1.3.2
- **LLM Wiki 项目知识层**：新增 `zscope/wiki` 子系统与 `zscope-wiki` CLI。扫描 workflow 在入口分析前执行一次 session 级 `wiki_compile`，把项目说明性 Markdown 确定性分类、按 heading 切分为稳定 source section，经不可变 revision 与原子 active pointer 发布；批量入口、Validator、Web 与 MCP 共享同一只读 `ProjectKnowledgeService`，Compiler 不可用或 Wiki 损坏时回退带路径、行号与 digest 的原文摘录查询。
- **自适应语义发现与 Validator v3**：balanced/deep 构建 Security Semantic Map，coverage-gap worker 在 candidate-blind 约束下主动提出 hypothesis；验证收敛为 V0 确定性 proof、V1 单次结构化判定、V2 定向补证复判与高风险 V3 有界调查（每 cluster 一个最长 50 次模型迭代的连续会话，仅白名单只读工具）。验证结论保留完整 reasoning，并新增 `user_rebuttal` 人工复议字段。
- **规则治理与 public config v2**：`zscope.yaml` 收敛为最小公共结构，Agent 拓扑、预算与稳定算法默认值移入可审计 RuntimeSpec；`rules.disabled_ids` 统一覆盖 Java local、C/C++ Regex/Clang/Graph、YAML pack 与 Python provider，且不抑制 backend signal 或 LLM 独立发现。
- **Clang 索引与 SVF 链路性能**：新增源码构建的 `zscope-clang-indexer` 批量前端（portable 包内随 LLVM 18 安装）与可选多实例 clangd 分片池；include-closure 作用域的部分派生重建、按 use-site 身份解析派生引用显著降低重复索引成本。SVF 支持可选懒 scope-first bitcode 构建、heap 预算内并行 Saber 分组执行，并跳过无法放进预算的 wpa 组。
- **Linux Portable 四包发布**：按架构（x86_64/aarch64）× 语言（cpp/java）交付四个解压即用的 portable 包，锁定 Ubuntu 23.10/glibc 2.38 构建基线，逐包附带 ABI 报告、SPDX SBOM、smoke 证据与签名校验和；旧 `install.sh` 分体资产仅保留兼容回滚。
- **可观测性与运维**：conversation-event v2 录制流逐事件记录 llm_client 行为；LLM 4xx 拒绝输出 wire-shape 诊断；批量报告携带 task id 与终端状态标记；SQLite 运行库下限明确为 3.8.10.2；正式 benchmark 与 Release 资产按发布 SHA 绑定。
- **Python 基线切换到 3.13**：`requires-python` 提升为 `>=3.13`，mypy/Black 目标同步 3.13；移除 Python 3.9–3.14 兼容矩阵、多版本带哈希约束与 CI workflow，规则 provider 的 3.9 `importlib.metadata` 回退一并清理。
- **用户配置推断增强**：resource/lock 推断覆盖 13 类风险接口角色，LLM 逐行筛选/修订/丢弃，低置信度行独立二轮复核（冲突标记 `llm:needs_review`），歧义符号定向分类，并生成 `user_config.infer_report.md` 审阅汇总；工作簿自带 README sheet。

### v1.3.1
- **版本与 Python 门禁**：包版本、CLI/MCP/Web 同步到 `1.3.1`，Python 3.9–3.14 使用独立带哈希约束和真实解释器 CI。
- **离线交付**：新增签名校验的一键安装器、CPython 3.13 应用包、按语言拆分依赖包、SBOM、许可证与升级/回滚布局。
- **Java Preview**：迁入 Java source/java_unified 索引、SootUp/WALA/Joern 信号接口、48 条本地规则和 58 条 truth（覆盖 49 个规则 ID）/54 个入口的结构 benchmark；`c047dca` 上已归档首个五轮 Preview LLM 基线，但不参与 v1.3.1 C/C++ 发布门禁。
- **统一规则扩展**：新增 `rule_pack_version: 1` YAML 校验、`zscope.rule_providers` entry point、语言隔离、重复 ID/未知 Skill 失败以及 `zscope-rules list|validate|test`。
- **候选生命周期 v3.3**：项目事实、结构化安全义务、validation group、occurrence alias 和 canonical outcome 进入单一流水线；正常完成时不允许残留 `pending`、`requested`、`running` 或 `validation_not_completed`。
- **确定性证据闭环**：新增 guard/边界、所有权/生命周期、锁/HB、调用契约等 proof provider。完整正向 proof 直接确认，完整反证才允许拒绝，证据冲突或缺失保守进入一个组级 `needs_review`。
- **低噪声根因投影**：`FindingRoot v1` 按结构化对象、sink/exit、decision region、代码和 proof 上下文投影 primary/alias，保留全部 occurrence 与 provenance，不使用 LLM 文本去重隐藏告警。
- **Validator token 收敛**：`ValidatorEvidenceSlice v2`、类型化补证、项目事实复用和最多两响应协议消除重复上下文及无边界浏览。五轮正式 Range 冷扫描 tokens 中位数为 1.324M。
- **发布门禁与证据**：五轮 WSL、自动入口发现、unified+SVF、GLM-5.1 正式扫描均完成 88/88 入口并通过硬门槛；Confirmed TP 中位数 89、raw FP 中位数 2、含复核 TP 固定 134。聚合和哈希清单保存在 `docs/range_reports/v33_release_final2_glm51_20260810/`。

### v1.2
- **版本号刷新**：包版本、README、架构文档和 Web 默认展示同步到 `1.2`。
- **Diff impact 精细化**：`--diff-repo-root`、重复 `--diff-path`、`project.diff_impact`、按 intent 的 caller 搜索深度、按需 `llm_triage`、`coverage_summary` 与 `function_coverage` 共同约束扫描 root，不再把所有反向外部路径都当成独立入口。
- **Unified/SVF 性能增强**：SVF entry scope 默认上限收敛为 200 TU，新增入口聚类布局缓存、bitcode/link manifest、互斥/共享 bitcode pool、link variant 记录和重复符号审计，批量入口可先共享 Clang 索引再延迟运行 SVF。
- **Clang 与 KnowledgeDB 增量鲁棒性**：Clang 后端用文件哈希跳过未变 TU，清理删除文件及其关联缓存，持久化 macro 定义；KnowledgeDB 增加调用图查询缓存、WAL/per-thread connection 和删除 TU 影响分析。
- **LLM 与验证链路提速**：LLM profile 支持多个 `base_urls`、每 endpoint RPM/并发上限、429/5xx cooldown 与累计 token 统计；Validator 增加 compact evidence fast-path、并行验证、entry-root retry 和更宽容的 JSON 解析；alert-verify 也可并行复核。
- **候选与去重精度增强**：本地/Clang/图候选新增或细化 fd 类型/编码契约、协议版本过滤、EAGAIN/EINTR 无预算重试、协议元素数与字节数错配、宏锁 no-op、部分资源重试失败清理等形态；语义去重继续使用类别家族、资源签名和 root-cause key 控制合并边界。
- **Benchmark 审计协议补强**：range ground truth 仍为 version 13 / 121 个有效漏洞；`zscope.benchmark.v3` 增加 false-positive audit 分类、duplicate-of-matched 拆分、suite-specific FP 审计规则和 benchmark 泄漏守卫。

### v1.1
- **版本号刷新**：包版本、README、架构文档、Web 默认展示和根配置样例同步到 `1.1`。
- **Diff impact 扫描落地**：新增 `--diff-base` / `--diff-head` / `--diff-path`，从 git diff 映射变更函数，按语义义务选择扫描 root，输出 `entry_functions_diff.json`、覆盖摘要和路径过滤 metadata，并在报告中标注增量、存量和影响待确认。
- **最终报告语义去重**：`reporting.semantic_dedup` 新增程序化同根因合并和可选 LLM 判重；报告保留 `semantic_dedup_summary`、`duplicate_sources`、`alternate_evidence`、`dedup_decisions`、`category_family` 与 `resource_signature`。
- **协议/运行时类候选扩展**：候选层新增对象发布顺序、语义单位错配、字节序逻辑、reader/global/slot/shared-memory race、lost wakeup、状态机、signal deadlock、callback self-destroy、文件类型验证和 FD 表示契约等规则。
- **Deep Worker 与预算控制细化**：新增 `subagent_max_turns`、`subagent_ticket_timeout`、`subagent_spawn_allowlist`、`subagent_skill_llm_refs`、`subagent_skill_efforts` 和 `tool_audit_log` 配置；风险预算会识别 thin facade 与 protocol/runtime callee，扩大必要的直接 callee 扫描。
- **Benchmark v13**：range ground truth 升级到 version 13，当前包含 121 个有效漏洞；评分协议支持把已命中 TP 的重复报告从有效 FP 中区分出来，并能读取嵌套 evidence location anchor。

### v1.0
- **首个正式发布版本**：版本号统一为 `1.0`，README、架构文档、Web 前端和 MCP `serverInfo.version` 同步展示 v1.0。
- **架构模块拆分完成**：原先集中在 `Analyzer` 与 `zscope/core/*.py` 的职责拆分到 `zscope/core/analysis/`、`zscope/core/candidates/`、`zscope/core/validation/`、`zscope/reporting/`、`zscope/common/issue_identity.py`、`zscope/memory/`、`zscope/semantics/`、`zscope/tools/` 和 `zscope/orchestration/`。
- **候选流水线稳定化**：`CandidatePipeline` 统一收集 local / graph / backend candidates；Clang AST/CFG、SVF value-flow、Joern CPG、KnowledgeDB call-edge 与用户语义 overlay 都进入同一 evidence-only 候选面。
- **稳定缺陷身份落地**：`canonical_issue_key`、`stable_issue_fingerprint` 与 source context fingerprint 统一服务报告去重、ReviewMemory、SARIF partial fingerprints、baseline 命中和 benchmark 匹配。
- **验证与反馈闭环收敛**：`ValidationRunner`、`ValidationPipeline`、`ReviewMemory` 和 `ReportAssembler` 明确分层；`verified` / `rejected` / `uncertain` / `needs_review` / `unvalidated` 的报告与 Web 复核语义保持一致。
- **Web 与用户配置工作簿升级**：Dashboard 增加项目配置、用户配置工作簿、看板和配置告警视图；`GET/POST /api/user_config/workbook`、`POST /api/user_config/workbook/import` 与下载接口支撑 `user_config.xlsx` 作为人工配置入口。
- **MCP 暴露面加强**：stdio MCP 保持本地集成；实验性 Streamable HTTP MCP 增加 bearer token 环境变量、客户端 allowlist、loopback 检查和 `ToolPolicy` 审计。
- **Benchmark 体系扩展**：range fixture 当前 ground truth version 10，包含 93 个有效漏洞；外部 benchmark harness 输出 `zscope.benchmark.v3`，记录双视图指标、matched pairs、stable identity、cost、trajectory 和多 trial 稳定性。

### v0.6.0
- **证据优先候选流水线成型**：新增 `DeterministicCandidateGenerator`，以通用 C 语言模式生成带 `candidate_id`、`dedup_key`、source/sink、正反证据和 `evidence_pack` 的候选，覆盖整数/边界、资源生命周期、时序内存、栈逃逸、空指针、锁与共享状态、格式串、命令注入和 stale fd/mmap 等问题。
- **跨函数图候选补强**：新增 `GraphCandidateGenerator`，从调用图、锁区域、生命周期协议和 liveness 形态中生成候选，覆盖跨函数递归锁、锁顺序反转、错误清理契约、线程参数生命周期、全局容器生命周期、timer/pipe 等级联等待和 stale tree/list 链接。
- **后端信号进入同一报告链路**：Unified 后端产生的 SVF/Saber/KnowledgeDB 信号会被规范化为 `backend_signal` 候选，与本地规则和 LLM finding 一起进入 CandidateLedger、Deep Worker、Validator、去重和报告输出。
- **风险自适应预算**：新增 `RiskBudgetPlanner`，把配置中的最大递归、预建模、图遍历和 Deep Worker 数量转为每入口 `effective_budget`，并在报告 metadata 中保留 `budget_scores` 与 `budget_reasons`，让低风险函数更轻量、高风险函数保留深挖空间。
- **KnowledgeDB schema v7 与 Inspection IR**：`code_knowledge.db` 新增 `ir_statements`、`ir_resource_events`、`ir_lock_events`、`ir_shared_accesses`、`ir_path_slices` 和 `function_contracts`，用于保存候选证据、路径切片、资源/锁/共享状态事件及评分组件。
- **三态验证与评分分层**：Validator 支持 `verified` / `rejected` / `uncertain`，Analyzer 计算 `final_score` 与 `score_components`。高分结果进入 `issues`；`needs_review`、`uncertain` 和验证失败的候选进入 `metadata.audit_observations`，默认不触发 CI 失败。
- **报告视图、根因去重与 SARIF 导出**：新增 `report_views.default` / `report_views.with_needs_review`，当时通过根因级去重合并重复 finding；CLI 新增 `--export-sarif`，可把完成后的 Z-SCOPE 报告导出为 SARIF v2.1.0。该去重链路在 v1.0 已统一到 `zscope/common/issue_identity.py`。
- **人工反馈闭环落地**：`UserConfigStore` 新增 `finding_suppressions` 与 `finding_baselines`。Web 仪表盘支持六种验证状态，并会把 `rejected` 写成误报抑制，把 `validated` / `needs_review` / `uncertain` 写成 baseline，后续扫描自动过滤或调整评分。
- **用户配置工作簿与推断链路**：移除批量 `prompt_autofill` 流程，新增 `user_config.xlsx`、`UserConfigWorkbook` 和 `--infer-user-config`。系统可推断 resource/lock API、多对多配对、dispatcher 分支、module lifecycle、pointer target 与 function intent，并在扫描时只注入相关配置片段。
- **入口发现结果落盘**：`--discover-entries` 会把候选入口、exposure、reasons、confidence 和审计提示写入项目根目录 `entry_functions_list.json`；`entry_discovery.search_root` 可把发现范围限制到指定目录（支持相对路径，固定基于 `source_root` 解析，且必须位于 `source_root` 之下）。
- **Range benchmark 回归体系扩展到 v6**：`test/range` 新增全局容器注册生命周期、scheduler/pipe 复合并发失败、嵌套 child-list 清理、AVL key 截断/陈旧节点和宏门控锁场景，总漏洞数提升到 45 个，并由 pytest 回归用例约束确定性候选覆盖率。
- **索引与构建鲁棒性补强**：Clang/regex 函数识别支持更多 C 声明修饰；`CodeIndex.get_function_impl()` 会附带声明/实现前导注释块，帮助 Agent 看到头文件契约；SVF bitcode 构建自动注入兼容 flag，并支持 `svf_scope` 入口裁剪、`llvm-nm` 符号闭包和 `bitcode_scope_<group>.json` 审计计划；Deep Worker 会接收结构化 evidence，Validator 输出兼容旧 `is_valid` 与新 `verdict` 格式。

### v0.5.0
- **全架构重构与扁平化**：扁平化了冗余的 `zscope/zscope` 目录结构，统一通过 `pip install -e .` 安装，更贴合标准 Python 打包规范。大幅强化三库同源（`code_knowledge.db`, `snapshots.db`, `user_config.db`）的底层持久化隔离与可观测性。
- **声明式工作流与智能体编排**：引入 `workflows/` 机制（如 default/maintain/resume 工作流）和基于 Markdown Frontmatter 的 `AGENT.md`/`SKILL.md` 契约。`zscope/workflows/*.yaml` 现在驱动实际执行步骤和 Agent 编排，报告 metadata 会记录 `workflow_progress` 与当前步骤。
- **Task 驱动的 Skill 选择**：`vulnerability_analyzer.task` 现在会解析用户关注点并限制本轮启用的漏洞挖掘 Skill。Agent 契约注入、Deep Worker 工单规划和最终 finding 过滤都遵循同一组 active skills，从源头减少用户不关心类别的检出。
- **批量 custom_prompt 自动补齐（历史能力）**：v0.5 曾提供 `zscope-prompt-autofill` 与 `PromptAutofillExecutor`，用于在批量扫描前补齐 `entry_functions_list` 中缺失或过短的 `custom_prompt`。该链路在 v0.6 已由 `user_config.xlsx` 与 `--infer-user-config` 取代。
- **C 内存/并发确定性候选层**：新增通用候选生成与证据包路径，覆盖边界/整数、资源生命周期、时序内存、栈逃逸、锁与共享状态等高价值缺陷，并接入 Deep Worker、Validator、报告分层和回归评测。
- **CLI Workflow 自动映射**：`--maintain` 自动选择 `maintain.yaml`，`--resume` 自动选择 `resume.yaml`。`analysis.workflow_name` 是运行时内部字段，禁止写入 `zscope.yaml`；两种 CLI 模式互斥，CLI 会提前拦截非法组合。
- **Deep Worker 启发式任务规划**：引入 `SubAgentOrchestrator`，基于启发式自动探测函数内的分配、拷贝、加锁等关键操作，先全量收集候选点，再按风险和预算下发给聚焦型 `Deep Worker`。未执行候选、失败/invalid/partial Worker 结果都会回传给主 Agent，避免预算截断造成静默漏检。
- **智能入口点自动发现**：新增 `--discover-entries` 特性。如果未给定分析列表，通过 `EntryDiscovery` 启发式扫描公共头文件 API、通信 IPC 接口、线程创建函数和标准 IO 输入源，自动推测最优的安全审计切入点。
- **原生支持 MCP (Model Context Protocol)**：内置本地 MCP stdio Server (`--mcp-stdio`)，对外暴露了 Z-SCOPE 专有的 `CodeIndex` 结构化查询、语义快照索引等能力，允许第三方 MCP 客户端（如 Claude Desktop）安全地调取分析底座的数据与工具链。
- **递归预建模与并发防护**：引入 `SnapshotLockManager`，在实际漏洞分析前通过 BFS 逆拓扑遍历，提前将所有可达子函数推给 `语义建模Agent` 并在多 Worker 间互斥上锁。彻底消除上下文膨胀问题以及多线程同时并发请求同一个下层函数的复述问题。
- **平凡函数旁路拦截器**：结合极简代码行数（默认 `≤5`）和危险关键字黑名单正则（杜绝 `alloc`、`lock` 等操作漏网），直接在调度层利用 Python 硬拼装阻断 LLM API 请求，实现零成本微快照注入，整体节约 `20~40%` 并发扫描 Token 开销。
- **引入 IssueReconcilerAgent 增量分析优化**。支持断点续扫（`--resume`）特性的完善支持。利用大语言模型（LLM）精准跟踪源码变更情况下历史已验证缺陷的存在状态；对扫描阶段产生的新缺陷进行语义级别的去重判决。
- **第三方告警标准化适配**：重构告警验证模式，引入统一的 `AlertAdapter` 适配层与 `ExternalAlert` 模型，轻松接入 Coverity/CodeQL/Cppcheck 等第三方 SAST 的告警确认。
- **严格类型与编译检查补强**：开发依赖新增类型存根，并固定兼容的 `mypy<2.0`。当前代码通过 `python -m mypy zscope` 与 `python -m compileall -f -q zscope scripts test` 检查，降低解释型语言冷门分支延迟暴露错误的风险。

### v0.4.2 (2026-03-05)
- **绝对行号注入法**：摒弃了大模型容易产生幻觉的相对偏移（Offset）行号计算，采用在源码侧直接注入绝对行号前缀的方式，将报告的定位精度提升至 100% 物理行级。
- **快照指纹抗扰动**：优化了语义特征的哈希计算逻辑，自动忽略源码中新注入的行号前缀，确保历史语义快照缓存持久有效。
- **跨环境扫描增强**：优化了 `rglob` 文件遍历逻辑，自动忽略因权限不足或 WSL 符号链接（如 `venv/lib64`）引发的 `OSError` 崩溃，大幅提升了在 Windows/WSL 混合环境下的扫描鲁棒性。

### v0.4.1 (2026-03-01)
- **SVF 3.2 兼容性**：更新 `svf_parser.py` DOT 正则以支持 SVF 3.x `{CallGraphNode ID: N \{fun: name\}|...}` 节点格式和端口化边引用。
- **SVF 3.2 saber 兼容性**：移除无效 `-uaf` 标志，新增 SVF 3.x `NeverFree/DoubleFree/...` 输出解析器（兼容 v2/v3）。
- **gllvm 环境自动检测**：`build_llvm.py` 新增 `_make_gllvm_env()` 自动检测 `clang-{version}` 并设置 `LLVM_COMPILER`/`LLVM_CC_NAME`。
- **WSL NTFS 兼容**：检测 `/mnt/` 路径时自动重定向 bitcode 输出到 Linux 原生临时目录。
- **SVF 共享库自动发现**：`svf_runner.py` 自动发现 SVF/LLVM `LD_LIBRARY_PATH`。
- **SVF 优雅降级**：SVF 工具不可用时输出框式告警并继续运行 Clang 部分。
- **修复**：`build_llvm.py` 中 `Path.with_suffix(".o.bc")` 改为字符串拼接，修复复合后缀不可靠问题。

### v0.4.0 (2026-02-28)
- **UnifiedBackend Facade**：新增 `unified` 后端，组合 ClangBackend + SvfAnalyzer，共享 KnowledgeDB，通过 `(file_path, line)` 坐标缝合 Clang AST 与 SVF LLVM IR 结果。
- **告警验证模式**：新增 `--mode alert-verify --sarif <file>`，导入外部工具 SARIF 报告，LLM 二次确认。
- **新增工具**：`get_deep_call_context`（高聚合查询：调用者+被调用者+间接调用+污点缺陷一次返回）。
- **KnowledgeDB schema v3**：`indirect_calls` 表增加 `call_file`/`call_line` 坐标列，新增 `find_function_at()` 和 `get_enriched_taint_bugs()` 缝合查询。
- **废弃 SvfBackend**：独立 SVF 后端已废弃，功能合并至 `unified` 后端。

### v0.3.0 (2026-02-20)
- **三种分析模式**：新增自上而下模式（`--mode topdown`）和规则驱动模式（`--mode ruledriven`）。
- **用户配置系统**：SQLite 存储外部函数描述、配对函数、函数指针指向、函数设计意图，分析时自动注入上下文。
- **Joern 异步 CPG 构建**：后台线程构建 CPG，支持 `--build-cpg` 预构建和 Web 端触发。
- **规则引擎**：集成 Joern `run.scan.toJson` 内置规则、自定义 `.sc` 脚本、配对函数检查。
- **Web 仪表盘**：新增配置管理（5 子页签）、CPG 状态监控、误报标记、配置告警展示。
- **误报反馈闭环**：按 `(function, location, subcategory)` 匹配，报告生成前自动过滤。

### v0.2.0 (2026-02-18)
- **重大重构**：代码索引后端从 clangd LSP 迁移至 Joern CPG。
- **新增工具**：`get_callers`、`get_type_info`、`get_call_graph`、`get_data_flow`、`find_function_pointers`。
- **依赖变更**：移除 `libclang`，新增 `cpgqls-client`。

### v0.1.0
- 初始版本：多智能体协作、语义建模缓存、模型自动降级。
