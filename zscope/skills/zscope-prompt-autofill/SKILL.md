---
name: zscope-prompt-autofill
description: Template for generating C custom_prompt values for Z-SCOPE batch entries.
category: orchestration
triggers:
  - entry_functions_list 中 custom_prompt 为空、缺失或过短
  - 用户要求为函数生成分析提示词或 custom_prompt
  - 用户提及 Z-SCOPE 提示词、分析提示、custom_prompt
allowed_tools:
  - list_known_functions
  - get_function_impl
  - get_call_graph
---

# Z-SCOPE Custom Prompt Autofill Template

This skill is read directly by `PromptAutofillExecutor`. Z-SCOPE does not load
extra `references/` files from a skill package, so all project knowledge needed
for prompt generation must be written in this file.

Before enabling `project.prompt_autofill`, copy this template and fill in the
sections marked `TODO`. Keep the filled content specific to your project, but do
not include secrets, credentials, private host names, or unrelated business data.

## TODO: Project Domain Vocabulary

Fill these lists with names used by the target C project.

- Allocation/create APIs: `TODO_ALLOC_API`, `TODO_CREATE_API`
- Release/destroy APIs: `TODO_FREE_API`, `TODO_DESTROY_API`
- Reference-count APIs: `TODO_REF_GET_API`, `TODO_REF_PUT_API`
- Lock/unlock APIs: `TODO_LOCK_API`, `TODO_UNLOCK_API`
- Message dispatch APIs or tables: `TODO_DISPATCH_API`, `TODO_HANDLER_TABLE`
- Global containers: `TODO_GLOBAL_LIST`, `TODO_GLOBAL_HASH`, `TODO_GLOBAL_BITMAP`
- Role/type fields that choose cleanup paths: `TODO_ROLE_FIELD`, `TODO_MODE_FIELD`
- Ownership-transfer conventions: `TODO_TRANSFER_RULE`
- Borrowed pointer conventions: `TODO_BORROW_RULE`

## TODO: Project-Specific Audit Rules

Replace the examples below with the real rules for the target project.

1. Allocation handlers:
   - If `TODO_ALLOC_API` succeeds, ownership is transferred to `TODO_OWNER`.
   - A later handler/function `TODO_RELEASE_HANDLER` is responsible for release.
   - Do not report a leak merely because allocation and release are in different
     handlers; verify whether the object is published to the documented owner.

2. Release handlers:
   - `TODO_RELEASE_HANDLER` is the paired cleanup path for `TODO_ALLOC_HANDLER`.
   - Verify that every global container attachment is detached under the same
     role/type condition used during allocation.
   - Verify that no borrowed pointer remains reachable after release.

3. Message dispatch:
   - `TODO_DISPATCH_API` routes messages by `TODO_MESSAGE_ID_FIELD`.
   - A prompt for dispatch functions should ask the analyzer to inspect all
     reachable handlers and ownership transfer across handler boundaries.

4. Conditional cleanup parameters:
   - Literal flags such as `TODO_TRUE_LITERAL`, `TODO_FALSE_LITERAL`, `0`, or `1`
     may select different detach/free branches.
   - A prompt should ask the analyzer to map the caller's role/type field to the
     callee's cleanup parameter and confirm the branch is correct.

5. Concurrency:
   - Global containers and lifecycle fields must be protected by
     `TODO_LOCK_API`/`TODO_UNLOCK_API` or atomics.
   - Callback invocation under locks must be treated as risky unless the callback
     contract is documented as non-reentrant and non-blocking.

## Function Classification Patterns

Use these patterns to decide what a generated `custom_prompt` should emphasize.
The final prompt should be Chinese, concrete, and evidence-oriented.

1. Message dispatch functions:
   - Names such as `*MsgProc*`, `*Dispatch*`, `*Route*`, `*Handle*`.
   - `switch/case`, handler tables, function-pointer arrays, or message-id maps.
   - Prompt focus: reachable handlers, ownership handoff, missing default/error
     paths, shared state touched by handlers.

2. Allocation or registration functions:
   - Names such as `Create`, `Add`, `Alloc`, `Apply`, `Register`, `Bind`,
     `Connect`, `Join`.
   - Calls to project allocation APIs, `malloc/calloc/realloc`, mmap, fd/socket
     creation, thread creation, or container insertion.
   - Prompt focus: partial initialization, publication before full init, rollback
     on failure, transfer of ownership to global containers or worker threads.

3. Release or unregister functions:
   - Names such as `Delete`, `Remove`, `Free`, `Release`, `Close`, `Destroy`,
     `Leave`, `Unregister`.
   - Calls to project release APIs, `free`, `close`, `munmap`, thread/join
     cleanup, or container removal.
   - Prompt focus: paired allocation path, stale aliases, double free, missing
     detach, role/type controlled cleanup branch, lock coverage.

4. Error, abort, or cleanup functions:
   - Names such as `Fault`, `Error`, `Cleanup`, `Abort`, `Rollback`.
   - Prompt focus: early returns, missing unlock/free/close, repeated cleanup,
     partially initialized objects, preserving original pointers after realloc.

5. Read-only query functions:
   - Names such as `Get`, `Query`, `Info`, `Stat`, `Find`, `Lookup`.
   - Prompt focus: borrowed pointer lifetime after unlock, stale fd/global map,
     reference count atomicity, cache invalidation by concurrent writers.

6. Initialization/finalization functions:
   - Names such as `Init`, `Fini`, `ResInit`, `ResFini`, `Start`, `Stop`.
   - Prompt focus: init/fini ordering, partially initialized globals, thread
     startup/shutdown, lock and condition-variable lifetime.

7. String, protocol, and copy functions:
   - Parsing serialized buffers, copying payloads, formatting paths/commands, or
     sending structs over file descriptors.
   - Prompt focus: length provenance, integer overflow, signed/unsigned
     conversion, terminator writes, padding disclosure, format strings.

## Prompt Style

Generated prompts should follow this style:

- Use Chinese.
- Use `(1)(2)(3)` numbering and usually 3 to 5 audit points.
- Name the concrete function and its observed role.
- Prefer source-evidence words: "跟踪", "验证", "确认", "反向检查".
- For cross-handler lifetimes, explicitly say not to treat documented ownership
  transfer as a same-function leak.
- For custom project rules, mention the filled project API/field names exactly.
- Do not reveal benchmark ground truth, expected bug IDs, answer-key files, or
  line numbers that are not derived from the analyzed source.

## Inline Prompt Templates

Allocation/registration handler:

```text
审计 {function} 的资源创建与发布路径：(1) 跟踪 {alloc_api_or_malloc}
成功后的所有权是否转交给 {owner_or_container}，跨 handler 生命周期不要按
同函数泄漏误报；(2) 检查部分初始化失败时是否释放已获得的内存、fd、锁或线程
参数；(3) 验证对象发布到全局容器/工作线程前是否完成初始化并具备锁保护；
(4) 反向确认配对释放 handler {release_handler} 是否覆盖同一角色/类型分支。
```

Release/unregistration handler:

```text
审计 {function} 的配对释放路径：(1) 将它与创建 handler {create_handler}
对应起来，确认所有全局链表/hash/bitmap/引用计数都按相同条件摘除；(2) 检查
释放后是否仍有全局指针、回调上下文、worker 参数或缓存引用可达；(3) 验证
重复调用、错误分支和并发 unregister 是否造成 double free、UAF 或死锁；
(4) 若释放 API 带有字面量参数，反向检查调用方字段到参数语义的映射。
```

Message dispatcher:

```text
审计 {function} 的消息分发链路：(1) 根据 switch/table/function pointer
枚举可达 handler，并跟踪消息体/上下文指针的所有权传递；(2) 检查默认分支、
未知消息、解析失败和 handler 返回错误时的释放/解锁；(3) 验证 handler 共享
全局容器或状态时是否使用一致锁顺序；(4) 不要只停留在分发表本身，要覆盖
被调 handler 中的内存和并发副作用。
```

Lookup/query handler:

```text
审计 {function} 的查询/借用指针语义：(1) 判断返回值是 owned、borrowed
还是引用计数对象；(2) 如果在解锁后返回内部指针，检查并发删除/重载是否会
导致悬空引用；(3) 验证引用计数增减是否在同一锁或原子操作下完成；(4) 对
未命中、错误返回和缓存失效路径做空指针与资源生命周期检查。
```

String/protocol parser:

```text
审计 {function} 的字符串/协议处理：(1) 跟踪长度字段、返回值和外部输入到
malloc/memcpy/memmove/read/recv/snprintf 的传播；(2) 检查加法/乘法尺寸计算、
signed/unsigned 转换和截断；(3) 验证栈缓冲区、终止符写入和结构体发送是否
存在越界或未初始化泄露；(4) 对错误路径确认已释放临时缓冲区并保留原始指针。
```
