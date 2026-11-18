# Z-SCOPE v1.3.2

[文档总导航](docs/README.md) · [使用指南](docs/guides/README.md) · [开发专题](docs/development/README.md) · [开发规划](docs/plans/README.md) · [历史归档](docs/archive/README.md)

**Z-SCOPE** 是一款基于 **多智能体（Multi-Agent）** 协作的 C/C++ 静态分析平台，并提供 Java Preview。它把可插拔代码索引、确定性规则、结构/值流后端信号、项目语义配置、人工反馈记忆与大语言模型（LLM）验证结合起来，模拟资深安全研究员的审计过程。

v1.3.2 在 v1.3.1 稳定线之上引入 LLM Wiki 项目知识层、自适应语义发现与 Validator v3 分层验证、跨语言规则治理和 Linux Portable 离线发布，并对 Clang 索引与 SVF 值流链路做系统性性能优化。当前主线采用 public config v3、独立的项目原语准备与审阅、分层 deep 发现及持久扫描计划；升级时需迁移旧工程根字段和语义工作簿，见[配置迁移](#配置迁移)。包内 `1.3.2` 是版本唯一真源，发布标签必须为 `v1.3.2`；`zscope.candidate.v3.3` 等字符串仅代表内部数据协议，不是产品版本。主线变更与历史发布说明见 [v1.3.2 发布说明](docs/releases/v1.3.2.md)。

## 核心特性

- **多智能体协作与声明式编排**：`AGENT.md` 与 `SKILL.md` 契约定义语义建模、漏洞扫描、验证、Issue Reconciler、Wiki Compiler 及聚焦型 Deep Worker 等智能体与技能，`zscope/workflows/*.yaml` 与 `WorkflowRunner` 驱动实际执行步骤。源码搜索、读取、语义上下文、图、流与静态发现六个证据工具由 `ToolPolicy` 统一做参数校验、敏感路径拦截与审计日志。
- **项目级静态发现与分层验证**：fast/balanced/deep 共享按 BuildContext/USR 去重的静态 pass 与低成本裁决；balanced/deep 对非 shadow 未闭合义务追加自主 Validator 调查，风险仅决定排序。deep 进一步构建函数→功能→模块契约摘要，在候选盲约束下提出新 hypothesis，并向已有候选提供待验证语义。所有来源统一进入全局 Candidate Ledger。
- **LLM Wiki 项目知识层**：扫描 workflow 在入口分析前执行一次 session 级 `wiki_compile`，把项目内说明性 Markdown 确定性分类、按 heading 切分为稳定 source section，并以不可变 revision 发布 Wiki 知识。批量入口、Validator、Web 与 MCP 共享同一个只读 `ProjectKnowledgeService`；Compiler 不可用或 Wiki 损坏时回退带路径、标题、行号与 digest 的原文摘录查询。`project.wiki.mode` 默认 `off`，`zscope-wiki` CLI 提供独立的状态、查询与维护入口。详见 [LLM Wiki](docs/modules/wiki.md)。
- **证据优先的候选流水线**：`CandidatePipeline` 汇总本地规则、Clang AST/CFG、SVF/Saber、跨函数图候选与 KnowledgeDB/Joern 后端信号，覆盖 fd 表示契约、raw/encoded fd 混用、EAGAIN/EINTR 无预算重试、协议元素数与字节数错配、宏锁编译为空、部分资源初始化失败回滚等模式。后端按语言隔离：C/C++ 默认 `unified`，Java 默认 `java_unified`；弱后端必须显式选择，深度后端失败不会自动降级。
- **跨语言规则治理**：Java 与 C/C++ 内置确定性检测器、YAML pack 和 Python provider 共用严格规则目录、canonical ID、Skill 校验与 `EffectiveRuleSet`；SVF/Saber、Joern 等仍保持 backend signal 身份，禁用规则不影响后端信号与 LLM 独立发现。
- **验证组终态与有界 Validator 协议**：`CandidateEnvelope v3.5`、`SecurityObligation` 和 scan-level validation group 按安全义务统一验证，并闭合为 `confirmed`、`rejected_with_proof`、`rejected_with_evidence`、`needs_review`、`engine_failed` 或 `interrupted`；确定性反证与有证据的模型反驳分别记录，引擎故障不会伪装成漏洞。每个 cluster 只传 bounded `ValidatorEvidenceSlice v3`：V1 是无工具、严格 schema 的单次判定，V2 按义务一次补齐事实后单次复判，V3 是最长 50 次模型迭代、仅白名单只读工具的有界调查；身份、引用、覆盖与业务前提未闭合时保持待复核。
- **稳定缺陷身份与 Canonical 报告**：`canonical_issue_key`、`stable_issue_fingerprint` 等统一身份服务去重、baseline、SARIF partial fingerprints 与 benchmark 匹配。`ReportAssembler` 只从冻结的 canonical outcome 集合生成默认视图和含复核视图；`FindingRoot v1` 仅合并 defect family、结构化 subject、decision region、代码与 proof 上下文完全等价的义务。CLI 支持 `--export-sarif` 输出 SARIF v2.1.0，Web 端可导出包含离线阅读器与逐 issue Markdown 的 ZIP 报告包。
- **运行模式与增量分析**：支持全新扫描（默认）、断点续扫（`--resume`）、增量维护（`--maintain`）与告警验证（`--mode alert-verify`）；diff impact 扫描（`--diff-base/--diff-head`）按变更意图选择最小必要扫描 root，并区分增量/存量发现。`--discover-entries` 自动识别头文件暴露的公共 API、网络收发、线程入口与用户输入点作为批量入口。
- **项目原语与反馈记忆**：C/C++ 以唯一的 `zscope.semantics.yaml` 维护用户声明的原语、经 native 事实推导的 wrapper、宏、函数指针槽与 dispatcher。`--discover-primitives` 只写入待人工确认的候选，正常扫描严格只读且只消费 `confirmed` 的精确 BuildContext/USR 契约；`pending`、`stale`、身份冲突或 YAML 中未闭合的间接绑定会阻止扫描。没有闭合目标集的 native 间接调用只进入机器 coverage gap，不生成无法确认的人工配置行；它不冒充已覆盖能力，并继续阻止 formal qualification。Web 复核状态仍独立持久化为误报抑制与 finding baseline，经 `ReviewMemory` 在后续扫描复用；机器证据位于 `.zscope_snapshots/semantics/`，不构成第二份人工配置。
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
    ├─→ 项目原语发现 --discover-primitives（--infer-user-config 为一周期废弃别名）
    └─→ MCP 服务 --mcp-stdio / --mcp-http
          │
          ▼
声明式工作流编排 (workflows/ + SpecRegistry)
          │
          ▼
CodeIndex (可插拔后端 + per-run cache) + ProjectSemanticsStore(YAML) + SnapshotStore + KnowledgeDB IR
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
          ├─→ deep 分层契约摘要 → candidate-blind hypotheses / 语义补证
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
5. **稳定身份、结构化根因与标准报告导出**：`candidate_uid`、`occurrence_uid`、`validation_cluster_uid`、`finding_root_uid` 和 `stable_issue_fingerprint` 分别服务候选、入口溯源、验证复用、报告投影与 baseline/SARIF。v1.3.2 报告保留 alias occurrence、入口路径、decision proof、affected subjects 和聚类遥测，便于复核每次确认、拒绝与合并。Web 前端可导出包含离线阅读器与逐 issue Markdown 的 ZIP 报告包；CLI 可通过 `--export-sarif` 输出 SARIF v2.1.0。
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

质量门禁固定使用 `mypy==1.19.1` 与 `black==26.10.1`，两者目标均为 Python 3.13；存量质量债务采用不可扩张基线管理。

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

构建基线为 glibc 2.38，运行时使用宿主 glibc；符号需求下限和实际测试下限分别记录在逐包 ABI 与 smoke 报告中。C/C++ 包包含 clangd 22.1.7，以及独立的 LLVM 18/SVF 3.2 bitcode 链路；Java 包包含 JDK 21、Maven、预编译分析 JAR 和 Joern Java 功能，不包含 Gradle。两份语言模板不展示工具路径，代码仍保留手工实验覆盖。发布目录支持移动和只读挂载。完整布局、源码安装、旧分体安装器兼容与制作流程见 [离线安装与发布](docs/guides/offline-installation.md)。Windows 用户通过 WSL2 使用 Linux 包。

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

首次接入推荐使用初始化器识别语言并查找编译数据库。TTY 中确认语言、目标 ID、编译数据库和扫描档位；CI 中使用非交互模式：

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

首次扫描前可以运行 `zscope-config prepare --config zscope.yaml`，或在 Web“项目配置”页保存配置后点击“检查已保存配置”。两处显示相同的实际配置/工程路径、编译实例数量、本地工具存在性、扫描深度、自动复现状态及产物目录；`--json` 提供相同结构化结果。检查只读，不启动模型、索引、扩展规则或加载历史运行策略；工具可执行性和模型连接仍由 doctor/实际运行确认。编译数据库有多个同源变体时会提示覆盖限制，不把命令数量当作完整扫描覆盖。

`--plan-entries` 只构建配置后端的索引，输出入口候选并写入项目根目录的
`entry_functions.discovered.json`；它不会调用 LLM 或执行漏洞扫描。若
`unified` / `java_unified` 缺少配置要求的深度工具链，doctor 和实际索引都会明确失败，不会静默降级到 regex。

#### public config v3

所有入口仅接受 `config_version: 3`，初始化器、模板和 Web 新建工程都默认 fast。C/C++ 最小结构如下：

```yaml
config_version: 3
llms:
  default:
    base_urls: ["${Z_SCOPE_LLM_BASE_URL}"]
    models: ["${Z_SCOPE_LLM_MODEL}"]
    api_key: "${Z_SCOPE_API_KEY}"
project:
  language: c_cpp
  platform: linux_user
  semantics_file: zscope.semantics.yaml
  targets:
    - id: main
      compile_commands: build/compile_commands.json
scan:
  preset: balanced
```

YAML 文件所在目录就是唯一工程根目录，目标的编译数据库使用相对此目录的路径。Java 使用
[`zscope.java.yaml`](zscope.java.yaml)，不填写编译数据库，默认预设为 `fast`，省略 scan 或 preset 也有效。
`zscope-init --preset fast|balanced|deep --target-id main` 可选择生成的预设和目标；
Java 只接受 `fast`。路径和目标标识按 YAML 字符串序列化，包含空格、`#` 或冒号的目录也可往返读取。

C/C++ 首次扫描固定使用以下流程；正常扫描不会现场发现接口、调用原语发现模型或修改语义 YAML：

1. 从 Web 一级导航“项目原语”开始引导，声明已知原语。表单从不调用模型的 native 接口目录选择精确函数，填写效果、载体、配对和条件；复杂契约可编辑高级 YAML。声明使用 `primitive: true`、`status: pending`，绑定前只用于发现。没有已知自定义原语时必须明确选择“没有”，CLI 等价命令为 `zscope-config review-semantics --config zscope.yaml --declare-none`，仍需执行发现。
2. 运行 `zscope -c zscope.yaml --discover-primitives`。命令遍历所有精确函数实例、宏、间接调用槽与 dispatcher，但人工 YAML 只接收效果跨函数边界可观察、ObjectPath 可精确映射且存在静态规则消费者的高信号接口。普通 `strlen`/`strcmp` 等 standard-operation 薄封装和只映射一个操作数的 copy helper 保留在 native 函数事实中，不制造人工门禁记录；当前仅实际被路径协议规则消费的 `access/stat/lstat/faccessat/fstatat` wrapper 进入 standard-operation 审核。dispatcher 只有在精确 handler 实例已经进入当前高信号接口闭包时才形成审核行，普通业务 switch 不会制造无关审核项。只有目标集已由当前 native/SVF 证据闭合的 pointer binding 才进入人工 YAML，未闭合调用记录为 coverage gap。确定性推导后只对首次出现、证据变化或仍有歧义的接口候选做一次 LLM 初审和最多一次事实补全；模型永远不能自动发布 `confirmed`。
3. 人工检查同一 YAML，将每条候选改为 `confirmed` 或 `rejected`。确认不仅是改 status：必须把 `cases` 收敛为结构化、可执行的谓词，并至少保留一个 `applies` 分支；全为 `unknown` 的候选不能发布。YAML 的 `op: true` 若要表达恒真必须写成字符串（建议 `op: 'true'`），布尔值会被拒绝，避免看似确认但运行时从未生效。源码、BuildContext、catalog、工具或证据变化后，旧决定会变为 `stale`。
4. 查看发现摘要和独立列出的覆盖缺口，运行 `zscope-config review-semantics --config zscope.yaml --complete`（Web 为“完成本轮审阅”）。零候选也需要此步。随后运行 `zscope-config prepare --config zscope.yaml`。CLI、Web、MCP、计划创建及实际启动共同核对发现收据、当前输入、人工完成摘要、pending/stale 与身份阻塞；审阅完成不代表机器覆盖完整。省略 `--complete` 的 `review-semantics` 只查看状态。
5. 正常运行 `zscope -c zscope.yaml`。默认自动发现入口用于可达性归因；需要固定入口时可使用项目高级设置；C/C++ fast 的项目级静态阶段仍对每个当前函数实例只分析一次，不把入口发现当成候选扫描边界。所有 preset 共用已确认的实例级 `ContractRegistry`；已复核 wrapper 的 `derived_from` 来源会随精确 BuildContext 编译为 delegate，供规则识别真实原语效果，不按 wrapper 名称授权。

旧 XLSX 只允许一次性迁移：`zscope-config migrate-semantics --config zscope.yaml --from-xlsx legacy.xlsx --output zscope.semantics.yaml`。命令保留原 XLSX，输出迁移报告；dispatcher 和 pointer target 必须重新绑定 native 身份，`module_lifecycle` 与 `function_intents` 只列入删除报告，其中函数意图改由 LLM Wiki 承载。

`zscope-config validate` 区分文档有效性与执行能力；多个 target 可完整校验、保存和逐项准备，
当前执行链一次只支持一个 target。focus、reproduction、platform 和 max_workers
仍是未消费的声明。配置 execution.stop_at 已由 CLI 和新建持久作业消费；显式作业窗口优先，
同 request_id 重放保留原窗口，resume 不重新套用配置窗口。作业启动的 CLI 采用该 attempt 保存的窗口；恢复后保存的空窗口表示本轮没有停止窗口。身份或输入已失效时拒绝启动。独立 CLI 仍使用配置窗口。这不表示完整 U01/S08 已完成。

CLI 的 `--scan-depth fast|balanced|deep` 覆盖本次 `scan.preset`，优先级为 CLI > YAML > 默认 fast。CLI 先验证 YAML，再覆盖档位；无效版本、字段或 Java 的 balanced/deep 不能靠 CLI 参数修复。两种语言省略 scan/preset 都使用 fast。档位不设置 scan-wide token 硬上限。

常用配置只需填写模型、语言和一个 target。需要精确控制时，可在同一 v3 文档添加 `indexing`、`concurrency`、`rules`、项目范围、Wiki 和 Review Memory 设置；不再维护第二套配置格式。

#### 配置字段参考

v3 的 CLI prepare/validate、初始化器和语言模板使用当前正式模型；结构化配置接口按正式 parser 校验文档，允许保存全部 targets，执行组合仍明确拒绝多目标。工程根目录固定为 YAML 所在目录；时窗解析为一次绝对边界。focus、reproduction、max_workers 和平台意图尚未消费，配置时窗已由 CLI 和新建持久作业消费，resume 不重新套用配置窗口；MCP 与其他消费端迁移仍有剩余，不能把其他已解析意图当作已执行能力。模型与接线边界见[配置模块](docs/modules/configuration-state.md)。

唯一公共格式为 `config_version: 3`。顶层允许 `config_version`、`llms`、`project`、`scan`、`execution`、`indexing`、`concurrency`、`rules`。除版本、模型和 project 的必填字段外，其余均可省略；未知键、重复 YAML 键、错误类型和跨语言字段严格报错。
所有字符串值支持 `${VAR}` / `$VAR` 环境变量展开，缺失变量在加载时即报错；
工程根目录固定为所加载 YAML 文件的父目录，项目内相对路径从该目录解析；
不再接受独立的根目录配置字段。Agent 启停、分析预算、deadline、缓存与报告策略不在
用户 YAML 中，由 RuntimeSpec 管理（见“内置 RuntimeSpec”一节）。

**`llms`**（LLM profile 表；`default` 必需，可按需新增命名 profile）

| 字段 | 默认 | 作用 |
|---|---|---|
| `base_urls` | 必填 | OpenAI 兼容 endpoint 列表；多 endpoint 按最闲优先分流，故障端点自动冷却 |
| `models` | 必填 | 模型列表，按序回退；非瞬态 4xx 直接切换下一个模型 |
| `api_key` | 必填 | 鉴权密钥，建议经 `${Z_SCOPE_API_KEY}` 注入而非写入文件 |
| `max_tokens` | 8192 | 单次响应 token 上限；不是 scan-wide 预算 |
| `context_window` | 192000 | 模型输入与输出合计容量；请按实际 endpoint 配置，不自动探测 |
| `model_context_windows` | `{}` | 按 `models` 中的精确模型名覆盖上下文容量；回退模型使用自己的窗口 |
| `timeout` | 120 | 单请求超时秒数；`null` 不限 |
| `max_retries` | 2 | 每个模型的常规重试次数（5xx/429/传输错误） |
| `retry_until_available` | false | 常规重试耗尽后对瞬态错误继续无限重试，直到成功或扫描取消 |
| `base_url_rate_limit_per_minute` | 不限 | 单 endpoint 每分钟请求数上限（60 秒滑动窗口） |
| `base_url_max_concurrent_requests` | 不限 | 单 endpoint 并发在途请求上限，与 `concurrency.llm_max_inflight` 共同生效 |
| `supports_structured_output` | false | true 时 JSON 输出走 `response_format`，false 时用 tool 强制 |

上下文窗口准入使用完整请求 UTF-8 字节数和消息开销作为未知 byte-fallback tokenizer 的保守容量上界，可能比实际 tokenizer 更早压缩工具正文。默认仍为 192000/8192；构建身份、证据引用和覆盖缺口不压缩。服务端仍报超窗时最多重投影一次，无法容纳则明确失败。

`scan.llm_profiles` 把 modeling/analysis/validation 三类角色绑定到命名 profile；
Wiki 编译器固定读取名为 `wiki_compiler` 的 profile（未定义时用 `default`）。

**`project`**

| 字段 | 默认 | 作用 |
|---|---|---|
| `language` | 必填 | `c_cpp` 或 `java`，决定其余字段的语言约束 |
| `id` | 空 | 报告与持久化状态的项目标识；空则取项目目录名 |
| `entry_function` | — | 单入口函数名；与 `entry_functions_list`、自动发现三选一 |
| `entry_file_path` | — | 可选；多个 TU 存在同名函数时指定实现文件消歧 |
| `entry_signature` | — | 可选；完整源码签名，用于区分重载/同名声明 |
| `entry_functions_list` | — | 批量入口 JSON 路径（相对 YAML 所在工程目录），优先级最高 |
| `include_paths` | `[]` | 源码扫描目录列表（相对 YAML 所在工程目录）；留空扫描整个工程，非空则替换扫描目录。不是编译器 `-I` 参数 |
| `exclude_paths` | `[]` | 排除的路径，命中的文件不参与扫描 |
| `platform` | `linux_user` | 当前只接受 Linux 用户态；保留平台意图，尚未改变执行策略 |
| `targets` | 必填 | 非空目标列表，每项 `id` 必填且唯一。C/C++ 还须填写 `compile_commands`（相对 YAML 所在目录或绝对路径）；Java 不填写。当前扫描只支持一个目标 |
| `semantics_file` | 初始化器写入 `zscope.semantics.yaml` | C/C++ 项目语义 YAML；相对 YAML 所在工程目录解析，扫描前须完成独立发现与审阅 |
| `user_config_file` | 历史字段 | 仅供旧工作簿定位与 XLSX 迁移；C/C++ 规则运行时不再从 XLSX 取得执行语义 |

`entry_discovery`（入口自动发现）：

| 字段 | 默认 | 作用 |
|---|---|---|
| `enabled` | true | 启用入口自动发现；显式 `entry_functions_list` 优先于发现结果 |
| `search_root` | `.` | 待扫模块目录（相对 YAML 所在工程目录），必须位于工程之内 |
| `interface_files` | `[]` | 相对 search_root 的 POSIX glob，限定视为公共接口的文件 |
| `max_entries` | 200 | 最多选出的入口数，其余候选标记 deferred 留待后续 |
| `max_functions` | 10000 | 候选函数枚举上限（Java 生效；C/C++ 仅作安全界，不截断入口） |

`project.wiki`（LLM Wiki 项目知识层；默认整体关闭，详见 [LLM Wiki](docs/modules/wiki.md)）：

| 字段 | 默认 | 作用 |
|---|---|---|
| `mode` | `off` | `off` 关闭；`build_only` 只构建不注入；`shadow` 记录同样的上下文选择但不改变结论；`active` 注入 Validator |
| `auto_maintain` | false | 源 manifest 未变化时是否自动重新编译维护 |
| `state_dir` | `.zscope_knowledge/wiki` | Wiki 状态目录；仅允许工程内相对路径 |
| `compiler_enabled` | false | 允许 LLM 编译器生成约束；false 使用确定性编译器 |
| `documents.exclude` | `[]` | 排除出 Wiki 语料的 Markdown glob（相对 YAML 所在工程目录） |
| `documents.classify.explanatory` | `[]` | 强制把匹配文档归类为可引用的说明文档 |
| `documents.classify.generated` | `[]` | 强制把匹配文档归类为生成物排除；同一 glob 不得与 explanatory 重复 |
| `max_file_bytes` | 10 MiB | 单个语料文件上限，超限跳过并记录 |
| `max_files` | 10000 | 语料文件数上限 |
| `max_total_bytes` | 100 MiB | 语料总字节数上限 |
| `compiler_max_tokens` | 不限 | Wiki LLM 编译器单次请求的 max_tokens 覆盖 |
| `max_wall_seconds` | 不限 | Wiki 构建的墙钟预算 |
| `max_constraints` | 不限 | 约束数量上限 |

`project.review_memory`（Validator 人工误报模式记忆；默认关闭，与 Wiki 语义隔离）：

| 字段 | 默认 | 作用 |
|---|---|---|
| `mode` | `off` | `off`、`archive`、`extract` 或 `active` |
| `state_dir` | `.zscope/review-memory` | 项目根相对的 Review Memory 状态目录 |
| `project_scope` | `project` | 仅允许项目级隔离 |
| `extraction` | `auto_extract` | `auto_extract` 自动后台抽取；`async_cli` 由 CLI 手动抽取 |
| `llm_enabled` | true | 是否允许抽取命令调用 LLM；反馈归档不受影响 |
| `max_patterns_per_finding` | 3 | 单个 finding 最大 advisory hint 数 |
| `max_context_tokens` | 1200 | Review Memory hint 的独立预算 |
| `stale_on_source_drift` | true | 源码上下文变化后停止复用模式 |
| `allow_direct_suppression` | false | 固定禁止 Review Memory 直接抑制 finding |

常用管理命令：

```bash
zscope-review-memory -c zscope.yaml list
zscope-review-memory -c zscope.yaml extract --enqueue
zscope-review-memory -c zscope.yaml jobs
zscope-review-memory -c zscope.yaml extract --job-id <job-id>
zscope-review-memory -c zscope.yaml replay <pattern-id> --input report.json --output replay.json
zscope-review-memory -c zscope.yaml export --output review-memory.json
```

抽取任务和 replay 结果写入项目级 Review Memory 状态目录；`replay` 是离线
advisory projection，不会启动 benchmark 扫描，也不会改变 finding verdict。

**`scan`**

| 字段 | 默认 | 作用 |
|---|---|---|
| `preset` | fast | `fast`/`balanced`/`deep` 三档分析深度（Java 仅 fast）；CLI `--scan-depth` 优先 |
| `task` | `""` | 空串启用当前语言全部适用 Skill；非空文本只指定审计重点 |
| `llm_profiles` | 三角色均 default | modeling/analysis/validation 到 `llms` profile 的映射 |

`scan.focus` 默认 `[memory, resources, async_lifecycle]`，`scan.reproduction` 只接受 `auto`；两者目前仅保存意图，不改变执行行为。

**`execution`**（可选）

| 字段 | 默认 | 作用 |
|---|---|---|
| `timezone` | 无 | IANA 时区，如 `Asia/Shanghai`；填写 stop_at 时必填 |
| `stop_at` | 无 | 本地 `HH:MM`，解析为下一个实际停止时间；DST 不存在或重复时间报错，不代表每日计划 |
| `max_workers` | 无 | 正整数，目前仅保存声明；实际并发请使用 concurrency |

**`indexing`**

`backend`：C/C++ 为 `unified`（clang 事实 + SVF 值流）、`clang`（仅 clang 事实）、
`regex`（纯正则索引）；Java 为 `java_unified`（结构前端 + 全部信号 provider）、
`java_source`（仅结构）、`joern`（仅 Joern CPG）。

| 子段 | 字段 | 作用 |
|---|---|---|
| `clang`（仅 C/C++） | `frontend` | `auto`（优先批量工具，缺编译数据库时回退 clangd LSP）、`batch`（严格批量，缺失即报错）、`lsp`；默认 auto |
| `svf`（仅 C/C++） | `scope` | `full` 全量链接；`auto`/`entry` 按入口可达性裁剪 TU（无入口时仍全量）；默认 auto |
| | `entry_depth` | 入口可达性裁剪的调用展开深度；默认 4 |
| | `max_selected_tus` | 单个分析组选中 TU 上限，超限触发 fallback；默认 200 |
| | `fallback` | `full` 超限/裁剪失败回退全量，`skip` 放弃该组 SVF；默认 full |
| | `groups_file` | 相对 YAML 所在工程目录的分组规划 JSON（组名到排除子串列表） |
| | `always_include` | 路径/子串模式，匹配的源文件无条件纳入 SVF 选择集 |
| | `exclusive_pools` | 互斥变体池 `{name, paths}`；同名符号多实现时按池拆分链接变体 |
| | `shared_pools` | 共享池 `{name, paths, conflicts_with}`，可出现在多个链接变体中 |
| | `heap_limit_mb` | 每个 WPA/Saber 子进程的堆上限；并发 worker 按此逐进程预留；默认 8192 |
| | `timeout_seconds` | 单个 bitcode/SVF 子进程超时秒数；`null` 不限；默认 1800 |
| `java`（仅 Java） | `structure_frontend` | `auto`/`spoon`/`javaparser`/`builtin` 源码结构前端；auto 按可用性依次尝试 |
| | `signals` | 图/数据流信号 provider：`joern`/`sootup`/`wala`/`codeql`；`java_unified` 要求全部配置项可用；默认 `[joern]` |
| | `extractor_command` | 覆盖结构提取 sidecar 命令（实验用；语言模板不展示） |
| | `provider_commands` | 按 provider 覆盖信号命令，stdout 须为 JSON（实验用） |
| `tools`（可选） | C/C++ | `clangd`、`clang_indexer`、`gclang`、`get_bc`、`llvm_link`、`svf_bin_dir`（wpa/saber 所在目录）；省略时按 PATH 或包内默认定位，显式配置无效时报错、不回退 |
| | Java | `joern.command`、`joern.host`、`joern.port`（默认 127.0.0.1:8080）、`joern.heap`（默认 `8g`） |

**`concurrency`**（可选，可只填需要调整的字段，全部正整数）

| 字段 | 默认 | 作用 |
|---|---|---|
| `entry_workers` | 4 | 并行分析的入口数，每个入口一套建模+分析会话 |
| `validator_workers` | 2 | Validator 并发验证线程数 |
| `investigator_workers` | 1 | deep_worker 子代理调查并发（默认由 RuntimeSpec 关闭） |
| `evidence_completion_workers` | 2 | 确定性事实补全 worker 数（不调用 LLM） |
| `index_workers` | 4 | 索引阶段并行度；C/C++ 同时决定 clangd 线程数 |
| `wiki_compiler_workers` | 4（可省略） | Wiki 编译并行度，仅 `project.wiki` 启用时使用 |
| `svf_workers` | 自动 | 仅 C/C++；SVF 分析组并发数，实际按内存预算收缩 |
| `llm_max_inflight` | 4 | 进程级 LLM 并发上限，与 profile 的 endpoint 限流共同生效 |

**`rules`**（可选，默认全空；治理语义见“规则目录与禁用”一节）

| 字段 | 作用 |
|---|---|
| `packs` | YAML 规则包文件路径（相对 YAML 所在工程目录） |
| `providers` | Python Provider 入口名 |
| `enabled_ids` | 显式启用默认关闭的规则 |
| `disabled_ids` | 禁用规则，优先于 `enabled_ids`；不抑制后端信号与 LLM 独立发现 |

#### 配置迁移

运行、校验、Web 编辑、MCP 和 benchmark 只接受 v3；不能只把旧文件的版本数字改成 3。一次性迁移命令将 v2 的 `scan.depth` 改为 `scan.preset`，`project.compile_commands_path` 改为 `project.targets[0].compile_commands`，保留模型、范围、规则、Wiki、并发等设置，并显式保留旧的入口发现开关和 SVF 内存默认值。

```bash
zscope-config migrate --input /path/to/project/old-zscope.yaml \
  --output /path/to/project/zscope.yaml
zscope-config validate --config /path/to/project/zscope.yaml
zscope-config prepare --config /path/to/project/zscope.yaml
```

- v2 未填写 depth 时输出显式 `preset: fast`；已填写的 fast/balanced/deep 保持原值。Java 的 balanced/deep 会报错，须改为 fast。
- 历史 v3 未填写 preset 时原 C/C++ 默认是 deep；如需保持强度，升级前补写 `preset: deep`，或运行同一迁移命令生成显式值。新配置省略时一律 fast。quick/overnight 仅在迁移中转换为 fast/deep，运行时无别名。
- v2 未填写编译数据库时生成 `compile_commands.json`（原自动查找位置）并提示核对；C/C++ 扫描仍须完成 `project.semantics_file` 的原语准备和审阅。配置迁移不替代此流程。
- 输出必须直接放在原工程目录，源文件始终保留；已有输出需显式 `--force`。候选配置先通过正式 parser，失败不会覆盖输出。环境变量引用保留原样，数值变量若无法结构校验会明确报错。
- 旧 v2 使用相对 `project.root` 时需提供 `--legacy-working-directory ORIGINAL_CWD`；历史 v3 相对根按原 YAML 定位。分离的 root/source_root 无法安全自动合并时停止迁移，先核对扫描范围。未知字段、混合新旧字段也报错，不静默丢弃。
- 无版本或 v1 配置不再自动转换；用 `zscope-init --output new.yaml` 生成新格式后按本节字段参考人工核对。迁移器仅负责一次性文件转换，正常加载不包含旧版本兼容逻辑。

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
知识库、快照和 `project.semantics_file` 均相对主 YAML 所在工程目录解析；C/C++ public v3 的语义文件必须留在该工程根内。

资源接口未识别或未参与检测时，可查看快照目录中的 `.semantic-modeling/publication.json` 的 `resource_inference_coverage`；报告 metadata 同时提供统计摘要。诊断区分未核验、条件未满足/未检查、缺 native 事实、消费者未支持的载体等原因，实际规则启用/执行情况仍见 rule catalog / engine coverage。其范围是本轮已调度函数；入口外清理路径未测量，零告警不代表全部资源接口已覆盖。此功能无需新增用户配置。

受限跨 TU 对象协议分析需要实际链接记录。在 Linux/WSL 中，可在项目目录显式执行以下准备命令，将参数替换为目标真实使用的对象文件与输出路径：

```bash
python -m zscope.cli.link_record --project-root . \
  --compile-commands build/compile_commands.json -- \
  clang build/a.o build/b.o -o build/app
# 更新安装后也可使用 zscope-link-record，参数相同。
```

此命令会按编译数据库重建所列对象并完成链接，记录保存在 `.zscope-link-targets/`；夜间扫描只读记录，不自动重建。当前支持同版本 Clang 编译和 native SDK、相容 ABI/编译参数的 C 对象直接链接；archive、shared library、LTO、复杂链接参数和未核验编译器仍显示缺口。源码、头文件、对象、产物或目标表改变后需重新记录并索引。记录不会开启实验规则；现有对象协议规则仍默认关闭。具体支持范围见[代码检索模块](docs/modules/retrieval-backends.md#已观察链接目标与受限跨-tu)。

资源建模也可核验受限的非原子引用计数，以及成功返回 1、失败返回 0 的单槽池归还接口，无需增加 YAML 字段。当前引用计数限 signed 32-bit 成员和已支持的池对象；drop 不直接表示 free，零计数后会检查实际清理对象与调用路径。显式启用对象协议实验规则时，相关报告会分别列出清理约定和非并发执行前提，集中在验收阶段核实；未知回调、原子/并发计数及未支持协议继续保留缺口。

自定义整数句柄表也支持受限源码核验：2–4 个固定槽，区分 close 失败前未消费与消费后报错、dup 共享底层对象但各自关闭，以及同一整数重开的新代次。句柄 0 可以有效；复制整数不等于 dup，关闭一个副本也不等于销毁底层对象。该能力复用已有实验规则，默认关闭；显式启用后的命名空间顺序独占、关闭责任及责任终点集中在验收时核实，无需新增 YAML。普通 OS fd、dup2/dup3 和并发关闭仍未纳入此具体路径；缺少平台证据时，标准 close 错误后的释放状态保持未知。

锁分析区分读锁与排他锁，并保留 try-lock 成功条件和 EOWNERDEAD 获取效果。读锁不作为写保护；对非逃逸静态锁和受限透明包装器，验证阶段可用当前编译事实核对全部本地访问。重复获取、锁升级、cond_wait、成员/动态锁及 C++ 锁 guard 暂留未决，不从“出现加锁调用”推断安全。相关实验规则仍默认关闭，无新增配置或夜间交互。

有限 C++ RAII 清理可用于核验泄漏候选：单一指针成员的局部 guard，从 malloc/calloc 对象接收指针，在析构中直接 free 或经当前源码核验的简单 deleter 清理。验证同时检查 native 构造/析构身份和当前 AST，区分空 guard、正常退出及函数内明确捕获的 throw；构建不明、move、release/reset、逃逸、未知 deleter 和未知异常仍待验证。它不授予锁保护或通用智能指针能力，也不要求新增 YAML 配置。相关候选规则仍默认关闭，实际核验依赖已有 checked-proofs 运行策略及匹配的 Clang 工具链。

实验性对象路径规则可检查受限 pthread 回调与单工作者队列：工作者取走任务并解锁后，调用方清空队列、停止接收或发出取消请求，仍可能在 join 等待期间访问已释放的旧对象。成功 join 后再释放的路径与之分开；即使两次操作使用同一 mutex，也不能排除串行发生的释放后访问。当前限 Linux glibc LP64、同 TU、默认属性、堆上下文及单槽队列的一个有界调度，按当前源码重放提交/取消 helper。已支持单等待者条件等待：释放锁、匹配通知、重新加锁，再按源码检查队列条件；提前通知不会累积成下一轮可用的通知。默认延迟取消可在 cond_wait/testcancel 处触发受限 C/glibc cleanup：等待锁先重获，清理按后进先出顺序运行，保留注册时的对象代次；pop(0) 仅移除、pop(1) 实际执行。同一 C 文件中的工作者直接 helper 可传递已知堆对象及受限整数，保留嵌套调用和暂停状态；取消时区分实际取消点与注册清理的调用层。缺通知、未取得 mutex、一般唤醒/超时场景、取消模式切换/任意取消点、一般 helper、多工作者或通用 drain 仍保留缺口，无告警不代表并发安全。沿用 `object_protocol_path` 的显式实验启用方式和集中验收页，不新增配置字段，实验规则默认关闭。

复查会重新核对头文件查找结果和当前资源契约。新增可选头文件、替换较高优先级头文件或增加共享变量访问者后，旧的排除结论不能直接沿用；资料不完整时回到待验证。热复查可复用有效 AST/CFG，但仍会运行预处理检查，离线历史报告不自动获得当前代码的证明资格。

动态复现当前仍默认关闭。开发模式启用 `runtime.analysis.dynamic_reproduction_mode` 后，会话服务可尝试唯一编译实例中包含自身 `main` 的原程序入口；计划、二进制及结果位于快照目录的 `reproductions/<session>/<candidate>/`。`shadow` 保存证据但不确认，`on` 也仅接受通过对象/站点/构建身份和独立重放核对的见证。多 TU 链接和通用输入生成尚未完成；构建失败、环境不可用或未复现都不表示程序安全。执行边界见[分析流水线](docs/modules/analysis-pipeline.md)。

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

`zscope-rules` 与 `zscope-config validate`、doctor、CLI、Web 和 MCP 共用同一套规则预检/序列化语义。规则目录、实现、禁用列表与扩展来源的 SHA-256 会进入配置、cache/Validator 身份和最终报告 provenance。扩展契约和开发测试见 [`docs/development/rules.md`](docs/development/rules.md)。

### Step 2：执行分析

运行入口由配置决定：未配置 `entry_functions_list` 且未启用 `project.entry_discovery.enabled` 时走单入口；配置了 `entry_functions_list`，或入口发现产生了候选时走批量入口。

```bash
# 单入口模式：从 entry_function 开始分析
zscope -c zscope.yaml --verbose

# 本轮启用 C/C++ balanced；token 只在扫描完成后计量
zscope -c zscope.yaml --scan-depth balanced

# --verbose 会把模型交互与工具调用录制到 .zscope_conversations/，
# 供事后审计 llm_client 与工具行为（事件字典与调优指南见
# docs/development/conversation-events.md）

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
# 需要显式指定 git worktree 根时，使用实际仓库路径
zscope -c zscope.yaml --diff-base origin/main --diff-head HEAD --diff-repo-root /path/to/git/root
# 只规划 src/net 与 src/fs 下的变更；必要的扫描 root 仍可位于路径外
zscope -c zscope.yaml --diff-base origin/main --diff-head HEAD --diff-path src/net --diff-path src/fs

# 基于已确认原语发现项目 wrapper、宏、pointer slot 和 dispatcher，然后退出
zscope -c zscope.yaml --discover-primitives
# --infer-user-config 是一个版本周期的废弃别名；同样只读/写 YAML，绝不再读写 XLSX

# 作为本地 MCP Server 运行（配合 Claude Desktop 等 MCP 客户端使用）
zscope -c zscope.yaml --mcp-stdio

# Coding Agent 只读盲调查（不初始化后端、不刷新语义、不允许扫描或报告访问）
zscope -c zscope.yaml --mcp-stdio --mcp-profile candidate_blind

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
| `.zscope_snapshots/security_map.db` | 历史或显式离线对照的 Security Semantic Map sidecar；当前默认分层发现不依赖该文件 |
| `.zscope_snapshots/security_semantic_map.json` | 旧地图路径的 coverage、unknown/conflict 与 audit unit 导出；文件存在不代表本轮启用了主动发现 |
| `zscope.semantics.yaml` | 人工维护的唯一 C/C++ 原语与项目接口权威；discovery 合并 pending/stale 候选，正常扫描只读 |
| `.zscope_snapshots/semantics/` | native/LLM 原始发现证据与 receipt；不构成第二份配置，不能直接授权规则 |
| `.zscope_snapshots/user_config.state.db` | finding suppression、baseline 与版本化业务前提回答；与项目语义授权相互独立 |
| `.zscope_knowledge/code_knowledge.db` | 代码索引、SVF/Saber 信号和候选证据 IR |
| `.zscope_knowledge/wiki/` | `project.wiki` 启用后的 Wiki revision 状态库与审计事件链（默认关闭；目录由 `project.wiki.state_dir` 决定） |
| `.zscope/review-memory/` | 人工 rejected finding、模式 proposal、审计和 replay 状态；不属于 Wiki constraint |
| `.zscope_bc/bitcode_scope_<group>.json` | SVF 入口裁剪计划，记录选中的源码、bitcode、可达函数、link variants、重复符号和回退原因；WSL/NTFS 场景可能重定向到 Linux 原生临时目录 |
| `.zscope_bc/entry_cluster_layout_<group>.json` / `bitcode_manifest.json` | SVF 入口聚类布局与 bitcode/link 缓存 manifest，用于复用未变化的聚类和构建产物 |

显式启用实验性 `object_protocol_path` 规则后，部分报告会列出尚待核实的业务前提。在 WebUI 打开该问题的“业务前提验收”，选择“成立／不成立／尚不确定”并填写接口规范或业务约定来源，即可一起保存该问题的回答。回答仅适用于列出的对象、入口、构建和源码版本；不新增 YAML 配置，也不会自动创建误报规则。保存后页面提示待重新核验，下次扫描会检查当前源码和回答版本；历史报告保持扫描时的结果。只有全部必要前提成立且技术证据完整时才能确认，否定前提不代表已证明代码安全。普通离线复核说明和状态修改不会被自动解析为业务回答。

集中验收按服务端证据展示已确认、条件性、待验证、已排除与覆盖缺口；未知覆盖显示未测。独立的重复标记、风险接受、后续待办和撤回记录保存在工程 `.zscope_acceptance/dispositions.sqlite3`，不改变验证结论、业务回答或误报规则。重复目标必须属于当前报告和同一构建；风险接受可过期，后续待办只保存在本地。报告证据或对象变化时，保存返回冲突并保留草稿，重新载入核对后再提交。

单函数最终报告的 `metadata` 会记录 effective scan depth、实际 consumed token、按 agent/stage 的 usage、finish reason、候选漏斗、发现/决策归因、Validator verdict transition、实际启用的发现阶段及覆盖缺口，以及现有 rule/candidate/diff/report-view 统计。`report_views.default` 只包含默认可报告问题，`report_views.with_needs_review` 会额外包含需要人工复核的观察项。有证据的模型反驳独立记为 `rejected_with_evidence`；缺少可解析引用、范围覆盖或仍有冲突的 rejected 保持 needs-review，不能被静默隐藏。

退出码由 `--exit-policy` 控制，默认 `review`：报告中存在确认缺陷或 needs-review 观察项时返回 `1`，`clean` 返回 `0`；`confirmed` 策略只对确认缺陷返回 `1`，`legacy` 沿用 issues 计数语义。阶段因超时、取消、工具失败等原因未完成时，结果仍会保存并标记 `completeness=partial`，CLI 返回 `2`；fast 中未请求的语义/主动发现阶段不会触发 partial。token 成本超出 Benchmark 预期不会截断产品扫描。

### Step 4：启动 Web 仪表盘（可选）

```bash
# 不需要先准备配置，先选择或创建工程
zscope --web

# 也可以直接打开已有配置
zscope --web -c /path/to/project/zscope.yaml
# 可选：--dashboard-host 127.0.0.1 --dashboard-port 8000
```

未传配置时先显示最近工程与“打开已有配置／创建工程”。目录浏览访问的是实际执行 Z-SCOPE 的机器；在 WSL 中选择 Linux 或 `/mnt/...` 路径，不是浏览器所在机器的上传目录。已有工程选择 YAML 或含 `zscope.yaml` 的目录；无配置时向导依次确认工程目录与语言、编译数据库、模型连接参数及快速／均衡／深度，生成配置后执行只读准备检查。向导不会覆盖已有 YAML，多目标执行和 Java 档位限制继续生效。

最近工程记录位于执行用户的 `~/.zscope/web/projects.json`，只保存配置路径、工程 ID 与最近打开时间等定位信息，不复制模型参数或密钥。选择工程后请求绑定其项目身份；不同浏览器标签页和项目的迟到响应不能写入另一工程。配置文件和实际扫描状态仍属于工程自身，不由最近列表替代。

Dashboard 当前作业入口为 `GET/POST /api/jobs`，复用工程侧持久 `ScanJobService`。Linux 上 MCP 的 `zscope.scan.run` 同样创建持久作业，必需 `request_id`，可选 `scan_depth`、带时区的绝对 `stop_at`；返回 `job_id`、`run_id`、`revision` 和输入绑定，重复请求重放同一作业。`zscope.scan.status` 必需 `job_id`。旧 Web `/api/scan` 的内存状态不能替代持久作业状态。接口不接受任意命令、环境、cwd 或输出路径。只读资源 `zscope://reports/latest`、`zscope://rules/effective` 保留。

持久作业使用 `GET/POST /api/jobs` 与 detail/events/result/cancel/resume，SQLite 状态和独立 owner 支持页面断开后重新读取真实作业。结果核对每次运行绑定的报告，未知分母/覆盖保持未测；重新尝试会重核输入，不保证只运行剩余队列，也不沿用旧停止时间。截止时先停止新增工作并有界收尾，必要时由 owner 终止扫描进程组；完整恢复与公平剩余队列的能力以实际报告为准。

v3 配置页可编辑工程、全部 targets、模型 profiles、preset 和执行意图；保存保留相对路径、环境变量引用及未编辑字段，空密码保留已有设置。保存失败时保留草稿，保存后重新检查配置。准备视图完整列出 targets、preset 映射与未消费设置；多目标可保存但禁止启动。单目标启动默认沿用保存的 preset。配置中的 execution.stop_at 作用于 CLI 和新建持久作业，任务的显式 stop_at 优先；同 request_id 重放保留原窗口，resume 不重新套用配置窗口。focus/reproduction/max_workers/platform 尚不代表已执行。

仪表盘默认打开项目概览，提供五个主要入口：

- **项目概览**：查看当前工程、最近任务、问题统计和覆盖状态，按当前状态提示下一步。
- **扫描任务**：检查已保存配置，选择快速／均衡／深度及单次或每日时间安排；“运行与历史”查看持久任务、结果、停止与重新尝试。普通重新尝试不继承上轮窗口；每日计划在新窗口重新绑定截止时间。
- **问题工作台**：保留上一轮已接入的问题队列、报告证据、复核与处置功能；本轮交互方案仍待取舍，没有把它列为本轮重做完成。人工复核、业务回答与处置各自保存，系统结论不由处置按钮改变。
- **覆盖与诊断**：查看逐编译实例、未完成范围、工具状态和配置告警。已记录缺口数量与覆盖测量状态分别展示，未知不表示零或安全。
- **项目设置与项目原语**：设置页编辑工程、模型并查看只读规则目录；项目原语页读写 `zscope.semantics.yaml`，提供独立发现、审阅和当前性检查。旧工作簿页面不再是 C/C++ 执行语义来源。

#### 扫描开始、截止与每日时段

扫描模式只有快速（`fast`）、均衡（`balanced`）和深度（`deep`）；时间安排独立于模式。可立即或在指定日期时间开始，结束条件可选直到完成或总截止时间；还可限制每天的开始与结束时段，支持 23:00–08:00 这样的跨午夜窗口与显式 IANA 时区。

持久计划使用 `/api/schedules` 与 `/api/schedules/cancel`。每日安排默认循环；仅当后台将真实作业判为完整完成才停止后续窗口，前端不会因进度条、零问题或窗口结束自行宣布完成。总截止已到但扫描未完整完成时，计划显示“截止已到”，真实作业仍独立显示部分完成等状态。直到完成明确不继承配置中旧的停止时间。

计划保存于工程 `.zscope_jobs/` 的 SQLite，独立 Linux 协调器在时段开始才启动既有作业 owner，窗口结束停止新增工作并有界收尾，下一窗口在同一作业下创建新的运行与 owner 身份。续作复用经核对的可恢复状态，不承诺只执行剩余项；输入或外部运行身份变化时阻止自动接管，需重新检查。取消默认同时请求停止仍匹配本计划的当前运行，选择只取消未来计划时则保留当前运行到其原窗口边界。

关闭网页或切换工程不会停止已启动后台；切换回原工程即可管理。关闭 WSL／执行主机或使其休眠则无法计算，重启后重新打开原工程可唤起保存的计划；这不是操作系统开机自启动服务。用户时段是否免费或优惠应向模型提供方确认。命令行守夜人也复用同一机制，例如 `python scripts/night_watchman.py --config /path/to/project/zscope.yaml --start 23:00 --end 08:00 --timezone Asia/Taipei --scan-depth balanced`。

#### 工程迁移到另一执行机器

把配置放在工程目录，项目内编译数据库、入口列表与规则文件使用相对路径，便于连同工程迁移；目标机器重新打开该 YAML，根目录自然变成新位置。最近工程列表是当前执行机的本地定位记录，需重新选择文件，不应复制旧绝对路径充当授权。

相对配置可迁移不代表所有缓存可跨机器复用：包含绝对路径的 `compile_commands.json`、链接记录、native 事实及其收据须在目标机用实际工具和编译输入重新生成或重建。历史报告可以留存阅读，新的执行与证据仍需核对源码、工具和 BuildContext；不能把另一机器的缓存直接当作当前有效事实。

页面、任务及问题支持 URL 定位与刷新恢复。链接仅用于定位，仍需校验报告、作业运行和输入身份；失效链接不会自动借用当前报告写入。问题复核草稿在当前页面的切换与迟到响应中保留，关闭页面前仍应保存；配置密钥不写入导航链接。

[新旧页面对照](docs/design/webui/index.html)提供匹配演示数据的桌面与手机截图、操作录屏、可点击原型和可导出的取舍清单。原型与截图使用合成数据，不代表真实扫描效果。

审计发现的详情采用连续 Markdown 报告，提供章节导航、独立纵向滚动、代码文件位置和行号。代码片段来源无法确认时标注“片段内行号”，证据记录编号不会被当成源码行号。

离线复核流程：

1. 先回写页面中尚未保存的验证改动，再点击“离线导出”，下载 `zscope-report.zip`。解压后包含 `index.html` 和 `issues/*.md`，每条 issue 一个文件。
2. 离线打开 `index.html`，点击“打开报告目录”选择解压目录。支持文件写入的 Chrome/Edge 可授权后直接保存 Markdown；不支持或授权失败时，使用“选择 Markdown / ZIP”，编辑后下载修改包。
3. 仅编辑验证状态与**本次人工反驳 / 复核说明**，说明支持 Markdown 预览。Validator 原文及已有人工说明保持只读。保存会检查磁盘文件是否被其他程序修改，失败时保留草稿。
4. 回到线上点击“导入”选择多个 `.md` 或 ZIP，也可“导入目录”。**本次说明缺失、为空或只有空白的 issue 始终跳过，即使其状态与线上不同。** 无冲突条目自动合并；冲突展示导出时、线上和离线的差异，由用户决定，确认时再次检查版本。

已应用的相同复核不会重复写入。导入只回写状态及本次说明，不导入修改过的证据或 Validator 正文；旧版单 HTML 请重新导出为 Markdown 包。单 `.md` 最大 16 MiB，单次导入总正文最大 128 MiB、最多 10000 条。

完整契约及接口示例见 [离线复核](docs/guides/offline-reviews.md)。

开发者可在 Linux/WSL 虚拟环境中安装 `python -m pip install -e '.[dev,browser-test]'`、运行 `python -m playwright install chromium`，再执行 `python -m pytest -q tests/test_issue_markdown.py tests/test_markdown_report_browser.py` 验证报告与离线交互。

## 分析工具清单（6 个证据导向 Agent 工具）

| Agent 工具 | MCP 名称 | 用途 |
|---|---|---|
| `search_code` | `zscope.code.search` | 默认搜索符号并返回稳定 `symbol_id`；`scope=text/files` 独立检索字面内容或文件路径 |
| `read_code` | `zscope.code.read` | 按 `symbol_id` 或明确的项目相对文件行范围读取带绝对行号的源码 |
| `get_semantic_context` | `zscope.semantic.context` | 读取或按需重建函数快照；`refresh_policy=cache_only` 禁止刷新；也可查询 Claim、Audit Unit、Semantic Map 摘要、编译实例及对应程序事实 |
| `query_code_graph` | `zscope.graph.query` | 查询 call、reference、callback 和 resolved indirect-call 关系 |
| `trace_data_flow` | `zscope.flow.trace` | 基于真实 def-use/CFG 或 Joern 证据追踪有界 source-to-sink 路径 |
| `query_static_findings` | `zscope.findings.query` | 查询 frozen CandidateLedger 和已持久化 backend signal，不启动新扫描 |

推荐调用链是 `search_code → symbol_id → read/semantic/graph/flow`；已有 `symbol_id` 时必须原样复用。列表结果按 `page.next_offset` 分页。所有调用返回统一的 `success/status/data/coverage/page/warnings/next_actions/error` 信封；`partial`、`unsupported` 和 `unavailable` 都不能解释为“没有问题”，`may` 路径和未验证 finding 也不能提升为已证明结论。

text/files 检索按返回 file/line 续读，分页还需原样携带 view_id；语料扫描完整度独立于结果页。只读消费可选择服务端 read_only/candidate_blind profile，具体语料许可、缓存限制、权限表与 Windows→WSL 项目级 Codex 配置见 [只读 MCP 接入](docs/guides/mcp-read-only.md)。

MCP 的证据工具使用上表中的 namespaced 名称；管理工具按下列接口提供，不暴露 raw 名称或重复 alias。管理工具包括 `zscope.knowledge.query`、`zscope.entries.discover`、`zscope.scan.run`、`zscope.scan.status`、`zscope.wiki.status`、`zscope.wiki.query`，以及 `zscope.jobs.list`、`zscope.jobs.events`、`zscope.jobs.result`、`zscope.jobs.cancel`、`zscope.jobs.resume`。作业工具仅在 `default` profile 提供，要求 Linux 后台和已保存配置；`read_only`、`candidate_blind` 不构造作业服务。events 使用 `job_id` 和可选非负 `after_seq`；cancel/resume 必需 `job_id`、`base_revision`、`request_id`，冲突语义与 Web 相同。显式 null 不是省略字段。result 目前提供本轮报告绑定，尚无 MCP findings 投影。多目标配置仍可编辑、不可执行；完整扫描队列接线和只执行剩余项仍未完成。MCP `2025-06-18` 返回 `outputSchema` 与 `structuredContent`；兼容 `2024-11-05` 时仍使用原生 `name/inputSchema`，但结果仅保留 text content。此次工具面切换是 breaking change，不提供旧名称兼容层。

示例：先找数值宏，再按返回 ID 读取完整定义。

```json
{"query":"MAX_RETRIES","kinds":["macro"],"match_mode":"exact","limit":20,"offset":0}
```

```json
{"symbol_id":"zs1:macro:<search_code 返回的摘要>","max_lines":200}
```

使用 native batch 索引时，可先向 `zscope.semantic.context` 传入 `{"kind":"build_contexts"}` 枚举编译实例，再传入 `kind=program_facts`、精确函数名 `query` 和原样返回的 `build_context_id` 读取该实例的程序事实。同名重载返回分页 `function_choice`，将选项的 native `usr` 原样作为 `query` 即可精确读取，不混合不同函数的事件。两种查询只读，不调用 LLM；输入变动时返回需重建索引的原因。同源多变体已独立存储，但完整扫描仍有按文件组织的消费者，不能把当前结果当成所有构建目标均已扫描。详见[构建实例边界](docs/modules/retrieval-backends.md#编译实例事实与导航投影)。

## 用户辅助配置

静态分析工具存在能力边界。C/C++ 的可执行接口语义必须进入 `zscope.semantics.yaml` 并通过 discovery/native 身份绑定与人工确认；反馈类状态继续由 Web 和状态库维护：

| 配置类型 | 说明 | 示例 |
|----------|------|------|
| 外部库函数描述 | 无法获取实现的外部函数的内存/并发行为 | `pthread_mutex_lock` 的锁语义 |
| 自定义配对函数 | 用户实现的 malloc/free、lock/unlock 等配对 | `my_alloc` ↔ `my_free` |
| 函数指针指向 | 函数指针、ops 表或 hook slot 的具体目标函数 | `handler_ptr` → `handle_read` |
| Dispatcher 分支 | 消息分发入口、message type、handler 及其资源 acquire/release 关系 | `MSG_APPLY` → `handle_apply` |
| LLM Wiki 上下文 | 模块生命周期、调用者约束和设计意图；只作上下文，不授权接口效果 | "此函数不会被并发调用" |
| Finding 抑制 | 对已确认误报按函数、位置、类别或规则进行抑制 | `src/demo.c:42` 的 `double_free` |
| Finding baseline | 记录历史验证结论，影响后续评分与过滤 | `true_positive` / `false_positive` / `needs_review` |

Web“项目原语”提供连续引导、六类常见原语模板、高级 YAML、后台发现任务、分页审阅和显式勾选的批量预检。它与 CLI 共用发现核心和 `ProjectSemanticsStore`，保留注释、顺序及扩展字段；相同证据下的人工决定可复用。保存绑定文档、条目和发现证据版本，冲突时保留浏览器草稿；发现与扫描同工程互斥。任务在关闭网页后继续，重新打开原工程可查看状态；关闭主机/WSL 不承诺继续执行。C/C++ 旧业务模型入口转至项目原语，支持工程内 XLSX 单向迁移并保留原工作簿。Java 显示“不适用”。Web 保存 finding 复核时仍维护独立的 `finding_suppressions` 与 `finding_baselines`，不能反向授予原语效果。

源码、编译依赖、根原语或 native 工具改变后，从同一页面重新发现并审阅。旧收据只有在包含可核验输入时才允许补做完成确认，否则要求重新发现。高级 YAML 不用于改写机器收据，函数意图进入 Wiki。实际界面、新旧入口对照、操作录屏和可导出的取舍清单见 [项目原语对照](docs/design/webui/primitives.html)。

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

大项目可安装独立的 `zscope-clang-indexer`，通过 `indexing.clang.frontend: auto|batch|lsp` 切换批量抽取与 clangd 回退。普通 bitcode 编译可直接使用与 SVF 配套的 Clang；覆盖盘点、资源预算、安装与测量命令见 [Clang 批量索引与 SVF 输入验收](docs/development/clang-batch-indexing.md)。

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

# 六工具 LLM 可用性评测：离线导出/评分已有 JSONL 轨迹
python scripts/evaluate_tool_use.py --emit-template /tmp/zscope-tool-use-traces.jsonl
python scripts/evaluate_tool_use.py --traces /tmp/zscope-tool-use-traces.jsonl --output /tmp/zscope-tool-use-score.json

# 真实 LLM 首次选工具评测；从环境读取 Z_SCOPE_API_KEY、Z_SCOPE_LLM_BASE_URL、Z_SCOPE_LLM_MODEL
python scripts/evaluate_tool_use.py --run-llm \
  --trace-output /tmp/zscope-first-tool-traces.jsonl \
  --output /tmp/zscope-first-tool-score.json

# 对已有真实轨迹仅重算首次工具选择与首次参数合法率
python scripts/evaluate_tool_use.py --traces /tmp/zscope-first-tool-traces.jsonl \
  --first-tool-only --output /tmp/zscope-first-tool-score.json

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

Agent 实施计划的开发评测准备使用 `python scripts/agent_plan_evaluation.py --help`。`plan` 生成无答案的冷/热/增量矩阵，`record` 冻结既有报告与用量账本，`compare` 核对源码、入口、构建、模型、配置与工具身份后比较。工具不启动扫描、不读取 truth、不评分；未知值保留 null、零分母显示 N/A，失败和重试成本保留。声明身份与报告实测绑定会明确区分；冻结记录内容变化会被拒绝。它不替代正式 benchmark 或完整 S09 验收，详情见 [Benchmark 模块说明](docs/modules/benchmarking.md)。

## 更新日志

### v1.3.2

以下记录版本早期能力；2026-11-02 主线的配置迁移、项目原语、分层发现和扫描计划变化见[主线同步说明](docs/releases/v1.3.2.md#2026-11-02-主线同步)，当前行为以上方使用指南与模块文档为准。
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
- **发布门禁与证据**：五轮 WSL、自动入口发现、unified+SVF、GLM-5.1 正式扫描均完成 88/88 入口并通过硬门槛；Confirmed TP 中位数 89、raw FP 中位数 2、含复核 TP 固定 134。聚合和哈希清单保存在 `docs/reports/benchmarks/v33_release_final2_glm51_20260810/`。

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
- **入口发现结果落盘**：`--discover-entries` 会把候选入口、exposure、reasons、confidence 和审计提示写入项目根目录 `entry_functions_list.json`；`entry_discovery.search_root` 可把发现范围限制到指定目录（支持相对路径，固定基于 YAML 所在工程目录解析，且必须位于工程之内）。
- **Range benchmark 回归体系扩展到 v6**：`test/range` 新增全局容器注册生命周期、scheduler/pipe 复合并发失败、嵌套 child-list 清理、AVL key 截断/陈旧节点和宏门控锁场景，总漏洞数提升到 45 个，并由 pytest 回归用例约束确定性候选覆盖率。
- **索引与构建鲁棒性补强**：Clang/regex 内部源码检索支持更多 C 声明修饰并附带声明/实现前导注释块，帮助 Agent 看到头文件契约；SVF bitcode 构建自动注入兼容 flag，并支持 `svf_scope` 入口裁剪、`llvm-nm` 符号闭包和 `bitcode_scope_<group>.json` 审计计划；Deep Worker 会接收结构化 evidence，Validator 输出兼容旧 `is_valid` 与新 `verdict` 格式。

### v0.5.0
- **全架构重构与扁平化**：扁平化了冗余的 `zscope/zscope` 目录结构，统一通过 `pip install -e .` 安装，更贴合标准 Python 打包规范。大幅强化三库同源（`code_knowledge.db`, `snapshots.db`, `user_config.db`）的底层持久化隔离与可观测性。
- **声明式工作流与智能体编排**：引入 `workflows/` 机制（如 default/maintain/resume 工作流）和基于 Markdown Frontmatter 的 `AGENT.md`/`SKILL.md` 契约。`zscope/workflows/*.yaml` 现在驱动实际执行步骤和 Agent 编排，报告 metadata 会记录 `workflow_progress` 与当前步骤。
- **Task 驱动的 Skill 选择**：`vulnerability_analyzer.task` 现在会解析用户关注点并限制本轮启用的漏洞挖掘 Skill。Agent 契约注入、Deep Worker 工单规划和最终 finding 过滤都遵循同一组 active skills，从源头减少用户不关心类别的检出。
- **批量 custom_prompt 自动补齐（历史能力）**：v0.5 曾提供 `zscope-prompt-autofill` 与 `PromptAutofillExecutor`，用于在批量扫描前补齐 `entry_functions_list` 中缺失或过短的 `custom_prompt`。该链路在 v0.6 已由 `user_config.xlsx` 与 `--infer-user-config` 取代。
- **C 内存/并发确定性候选层**：新增通用候选生成与证据包路径，覆盖边界/整数、资源生命周期、时序内存、栈逃逸、锁与共享状态等高价值缺陷，并接入 Deep Worker、Validator、报告分层和回归评测。
- **CLI Workflow 自动映射**：`--maintain` 自动选择 `maintain.yaml`，`--resume` 自动选择 `resume.yaml`。`analysis.workflow_name` 是运行时内部字段，禁止写入 `zscope.yaml`；两种 CLI 模式互斥，CLI 会提前拦截非法组合。
- **Deep Worker 启发式任务规划**：引入 `SubAgentOrchestrator`，基于启发式自动探测函数内的分配、拷贝、加锁等关键操作，先全量收集候选点，再按风险和预算下发给聚焦型 `Deep Worker`。未执行候选、失败/invalid/partial Worker 结果都会回传给主 Agent，避免预算截断造成静默漏检。
- **智能入口点自动发现**：使用 `--discover-entries` 时，`EntryDiscovery` 扫描公共头文件 API、通信 IPC 接口、线程入口、注册回调和标准 IO 输入源。`signal` / `sigaction` 的处理函数及 `atexit` / `at_quick_exit` / `on_exit` 的退出回调作为 `callback` 入口；支持源码可解析的嵌套函数封装和参数转发，信号回调保留异步信号审计上下文。
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
- **工具增强**：增加高聚合的调用、间接调用和静态信号调查能力；该历史接口现已由六工具证据契约取代。
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
- **工具增强**：增加调用、类型、图、流和函数指针调查能力；这些历史入口现已收敛到六工具证据契约。
- **依赖变更**：移除 `libclang`，新增 `cpgqls-client`。

### v0.1.0
- 初始版本：多智能体协作、语义建模缓存、模型自动降级。

### 项目原语发现与实例级契约

原语发现与漏洞扫描是两个独立命令。Discovery 以当前系统头/USR/签名/BuildContext 验证的 packaged catalog 以及 YAML 中人工确认的项目原语为根，遍历项目全部精确函数实例，在 link group/SCC 上组合直接或多层 wrapper、宏、条件效果、ownership transfer、realloc、引用计数、FD/handle、锁模式、taint、函数指针与 dispatcher。dispatcher 候选同样受这条根化闭包约束，只保留连接到已推导接口实例的精确 handler 分支。函数名相似只参与排序，不能生成可执行语义。

YAML 的 effect 使用结构化 ObjectPath（return/argument/global、pre/post、解引用层数、成员路径）以及显式 `must_under_guard`/`may`。资源配对属于接口自身的 `pairs`；每个 effect role 必须存在规则适配器。Discovery 可记录模型的 `agree/refine/disagree/insufficient` 建议，但 status 保持 pending；只有人工确认且当前 native 证据仍匹配的契约才编译进实例级 Registry。闭源 `external_model` 是明确标注的用户假设，不伪装成 native 证明。

普通扫描不会执行 discovery、调用接口发现 LLM 或修改 YAML。源码、构建、catalog、native 工具或证据变化使旧决定变为 stale；不同编译变体不复用，unknown build 不是通配符。规则按 resolved call-site effect 查询统一 Registry，不再以散落名称表识别项目 malloc/free/lock wrapper。报告记录 catalog/YAML 摘要、逐构建授权和拒绝、consumer、pointer/dispatcher 精度及覆盖缺口。

### 共享报告与接口审核

默认 JSON 报告是完整自包含的共享对象格式。Python 集成用 `zscope.reporting.json_io.read_report(Path(...))` 读取，新旧格式均返回相同逻辑字段；外部只支持旧 JSON 的工具可先完整导出：

```bash
zscope-report export --input report.json --output report.legacy.json --format legacy-json
```

`zscope.semantics.yaml` 列出无法由实现证据自动发布的项目接口。检查 selector、BuildContext variants、源码证据、条件和 effect 后，可将 status 改为 `confirmed`；下一次扫描把它编译为实例级人工契约，并沿已核验映射静态传播。`pending`、`rejected`、`stale` 均不生效；确认接口角色也不能替代某次运行时调用成功的程序证据。

条件等待的受限分析还会在默认通知路径未闭合时，尝试最多一次无通知唤醒或 `pthread_cond_timedwait`/`pthread_cond_clockwait` 超时。只处理当前 native 核验的函数局部 timespec、有效纳秒范围，以及 timedwait 默认 CLOCK_REALTIME 或 clockwait 直接系统 CLOCK_REALTIME/CLOCK_MONOTONIC 常量；返回前重获锁，之后按源码检查返回值和队列条件。报告保留选中分支、尝试范围及截止时间/时钟前提，在现有验收页集中确认。自定义时钟、任意截止时间来源、多次唤醒序列和一般错误结果仍未覆盖。

受限单工作者队列分析现可跟踪调用方通过条件变量等待活动任务退出：只接受匹配通知、原锁重获和源码条件重检。报告仍会指出提前清零活动标志、收到通知后工作者继续访问对象，以及 free 后才开始等待的问题；等待返回不会自动视为线程已结束或 join。调用方超时/无通知返回、取消和通用注销协议继续保留覆盖缺口，业务前提仍在现有验收页集中确认，实验规则默认关闭。
