# P01 / K02：G2 集成验收

HEAD/分支保持 G0。完整 argv、输入 SHA256 和计数在 `P01-K02-G2-validation.json`。总控冻结相关源码后执行组合：**353 passed、0 failed、0 skipped、3 deselected，exit 0**，前后输入摘要一致。被明确排除的三个重型用例已在独立拥有的临时目录分别实际通过：P01 八类 native mutation、P01 bitcode/WPA/Saber 兼容 smoke、K02 native 索引到契约消费链；并非未验收便跳过。

组合覆盖索引身份/增量/缓存、条件契约/wrapper/发布、语义链、严格配置和交接文档。P01 三文件、K02 三文件的专项 mypy/compileall/格式及 diff 检查通过，详见各自独立 record。新 D02 内部配置的配置边界用例也在本次组合通过，但 D02 Worker 仍在实施，不能因此登记 D02 完成。

P01 的五次隔离 function_body 采样在全体停止源码写入及其他测试后执行，输入与工具摘要稳定；不外推大仓或 SVF 性能。实际 LLVM/SVF 补验首轮暴露直接 WSL 进程缺少动态库搜索路径，未运行测试；单次进程显式设置现有 LLVM/SVF 库目录后实际通过，未安装或更改全局环境。原 skipped 和失败 preflight 仍留在 P01 record。

第一次组合功能测试同样 353 passed，但总控记录脚本的收尾循环重复计算整树摘要，已停止该拥有的进程；当次未认定 G2。修正记录脚本后用新临时目录重新执行，以上为完整最终结果；两轮不相加。此前 D02 配置测试的临时 public fixture 漏填必需 concurrency 字段（54 passed / 1 failed）也已修正并在本次组合通过，未放宽产品 schema。

G1/G2 与对应本地真实工具验收通过，P01/K02 登记 done，解锁 V01。P02 仍等待 D03；R01/R02 启动条件另行留账。真实模型、正式 Range、大仓性能及 portable smoke 均 not_run；全仓最终质量检查在本批合流时单列。
