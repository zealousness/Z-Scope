---
doc_contract: zscope-module-v1
covers:
  - zscope/retrieval
sources:
  - zscope/retrieval/code_index.py
  - zscope/retrieval/knowledge_db.py
  - zscope/retrieval/clang_backend.py
  - zscope/retrieval/joern_backend.py
  - zscope/retrieval/unified_backend.py
  - zscope/retrieval/java_source_backend.py
  - zscope/retrieval/java_unified_backend.py
  - zscope/retrieval/java_signal_providers.py
  - zscope/retrieval/svf_analyzer.py
tests:
  - tests/test_code_index_cache.py
  - tests/test_clang_incremental_extraction.py
  - tests/test_knowledge_db_ir_and_config.py
  - tests/test_svf_cache.py
  - tests/test_joern_client.py
  - tests/test_java_source_backend.py
---

# 代码检索与后端

## 职责与非职责

本子系统负责把 C/C++ 或 Java 源码、编译数据库和外部分析器转换为可查询事实：函数、类型、调用边、AST/CFG、间接调用、指针/值流、结构/信号 provider 和缓存状态。`CodeIndex` 为上层提供统一门面；C/C++ 使用 regex、Clang、Unified，Java 使用 java_source 或 java_unified。

它不负责决定候选是否成为最终漏洞，不负责模型提示词，也不负责报告视图。

## 主入口和数据流

- `CodeIndex` 负责源码发现、缓存、后端创建和统一查询接口。
- Clang extractor/backend 写入结构化函数、类型、调用边和增量索引信息。
- `KnowledgeDB` 持久化代码事实和后端 IR，并维护版本化查询缓存。
- Java source backend 提供方法、注解和框架结构；java_unified 叠加 SootUp、WALA、Joern provider evidence。
- C/C++ Joern 在 1.x 中仅为弃用兼容入口，不属于默认或离线 C 工具链。
- Unified backend 组合 Clang 与 SVF；bitcode scope、LLVM 构建和 SVF runner 负责入口裁剪、链接与分析。
- 上层候选和 Tool runtime 只消费统一查询结果，不应依赖某个后端的私有输出文本。

## 必须保持的不变量

- 后端能力不足必须返回明确的空结果、告警或降级状态，不能伪造完整能力。
- Java provider 信号只能进入 Java 分析路径；CodeQL 为 BYO，不得进入官方依赖包。
- Java Spoon 默认复用已准备的本地 Maven 缓存，不隐式强制联网刷新；显式刷新只允许发生在联网准备阶段，sidecar 不得在目标项目遗留 `spoon.classpath.tmp`。
- 日常 Joern WebSocket 查询必须有总量可控的超时和重试边界；CPG import 可以使用独立的长时限，不能把一小时等待传播到普通入口查询。
- 增量索引以文件/TU 变化为依据；删除文件必须清理旧函数、类型、调用边和缓存。
- KnowledgeDB 写入新事实后必须使相关查询缓存失效。
- Unified 的 Clang 与 SVF 结果必须通过稳定的文件、函数和位置坐标缝合。
- bitcode 裁剪、符号闭包、共享/互斥 pool 和回退原因必须保留 manifest 供审计。
- 遍历目标项目时要容忍权限错误和无效链接，但不能越过配置的源码范围读取敏感路径。

## 常见变更应落到哪里

- 新索引查询或缓存：`code_index.py`、`knowledge_db.py`，同时更新调用工具测试。
- Clang AST/CFG 或增量行为：`clang_extractor.py`、`clang_backend.py`。
- Joern CPG 查询：`joern_backend.py` 和公共 Joern client。
- SVF/Saber、bitcode 或工具发现：`svf_*`、`build_llvm.py`、`bitcode_scope.py`。
- 多后端合并和能力 gate：`unified_backend.py`、`backend_base.py`。

## 对应测试与验证命令

```bash
python -m pytest -q tests/test_code_index_cache.py tests/test_clang_incremental_extraction.py
python -m pytest -q tests/test_knowledge_db_ir_and_config.py tests/test_svf_cache.py
python -m pytest -q tests/test_joern_client.py tests/test_bitcode_scope.py
```

## 权威源码和关联文档

- 稳定入口见本文 frontmatter 的 `sources`。
- 后端定位与能力矩阵见 `README.md` 和 `docs/architecture.md` 的“事实平面”。
- WSL 特有问题见 `.agents/workflows/wsl-pitfalls.md`；原生 Linux 不应套用 WSL/NTFS 假设。
