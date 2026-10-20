# V01 只读缺口与隔离审查

日期：2026-10-08。批次 parallel-20261008，Agent C。当前未实施 provider/runner，未编译或运行缺陷 fixture。

## 可复用接口与缺口

`zscope/common/validator_protocol.py` 已存在 DynamicReproductionRequest / DynamicReproductionResult；request 当前明确 reserved_not_implemented，结果使用 reproduced / not_reproduced / inconclusive / failed。新增独立 provider/runner 应复用它们并携带执行 receipt，不改 ValidatorResult v3 或产品 disposition，不把 not_reproduced 当安全反证。

缺口为：可验证的执行计划身份、受控 argv/环境/工作目录、独立隔离执行、资源/超时/取消边界、真实 ASAN 分类及候选对象/站点绑定、二进制和源码摘要、原始 artifact 与重放。公共 validation runner/pipeline 接线归总控；Agent C 实施独立模块、fixture、测试。已有 proof registry 不接受模型自报日志作为动态 witness。

## 只读环境核验

实际使用 WSL Ubuntu 与 `/home/zeal/venv313/bin/python`。固定 PATH 为 venv、Go、LLVM18、SVF、系统目录；不依赖 Windows 或登录 shell 差异。

| 探针 | 结果 | 退出码/限制 |
|---|---|---|
| GCC 版本 | 13.3.0 | 0 |
| Clang 登录环境版本 | 18.1.3 | 0 |
| GCC libasan.so / libtsan.so | 文件存在 | 未执行 instrumented binary |
| Clang18 ASAN/TSAN runtime | 文件存在 | 未执行 instrumented binary |
| wpa/saber ldd | 无缺失共享库 | 0 |
| cbmc / goto-cc | 未找到 | 不安装 |
| podman --version | 4.9.3 | 0 |
| `podman info --format '{{.Host.Security.Rootless}}'` | true | 0；提示 / 不是 shared mount |
| `podman images --format '{{.Repository}}:{{.Tag}} {{.ID}}'` | 本地已有镜像 | 0；未拉取镜像 |
| `unshare --user --map-root-user --net -- true` | 无输出 | 0；只运行 true |

已有可候选镜像：`localhost/zscope-portable-builder:x86_64`（ID e227baaabba6）、`python:3.13`（ID 1cbbca32768c）、`python:3.13-slim`（ID 9351a9a0a697）。存在镜像不代表已经验证断网、只读挂载、资源限制或 sanitizer 兼容性。完整固定镜像 digest 应在实际执行前读取并登记。

三个 LLM 环境变量均未设置。当前不需要模型服务。

## 后续门禁

先 fake 验证计划错配、原始日志伪造、错误候选 crash、退出码、超时/取消和旧二进制拒绝；总控解锁 V01 且发放唯一重型名额后，才对已有镜像执行离线隔离探针及独立受控 ASAN 正反例。运行时固定 `--pull=never`、断网、只读输入、专属临时可写目录；真实资源/隔离限制以实际证据记录，不把 subprocess 称作容器隔离。

缺失运行条件时 fake 仍可继续，真实执行 not_run/blocked，不能标完整验收通过。V02 首选已有 TSAN runtime，独立构建而不与 ASAN 混用；CBMC 暂缓。

implementation_status: not_started

verification_status: environment_probe_passed; real_execution_not_run
