# ZCode S09 原范围受控恢复

父任务最新明确授权正常子进程 ZCODE_BIN/ZCODE_NODE/ZCODE_PROVIDER/ZCODE_MODEL 四项启动修复与原 S09 范围恢复；不修改持久配置、原生包、凭据或 provider/baseURL。详见 ROUTE_DIAGNOSIS.md。

单独官方标准 MCP 客户端 PID 94576（--route-check --zcode-bootstrap），不重启 Kimi 主桥 PID95496。公开 check_task 再次核对原 task_f531d6882c 为 failed/persisted，files_changed 已 collected，只有桥日志/进程记录与 sandbox 状态，无 S09 产品文件；get_result 原有记录为空。诊断记录只有 lazy alias、无物化 zcodeSid 与对应 backend 日志，历史 prompt_may_have_been_sent=true 保留，不把无日志当绝对无HTTP证明。

list_agents 预检公开 ZCode available=true/version0.67.0，明确 wrapper；这是入口可用性，不能作为模型 HTTP 或开发交付通过。恢复仍使用原 hw UUID/glm-5.3完整 selector，并须 ACP 接受该 selector 后才发提示；禁止默认模型/路由回落。新错误停止分支，不换模型或绕行。

ENTRY_BINDINGS dispatch_ready 只表示此显式 bootstrap 模式下原范围恢复获准，不表示实际采样/HTTP 成功。client guard 仍要求 --route-check 与 --zcode-bootstrap，核对 wrapper/provider registry 摘要、版本和当前既定映射；其他实例不热加载设置。请求持久 journal 与 consumed 标记避免重复发送。
