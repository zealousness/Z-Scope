# V01/V02 资源返修准备与外发阻碍 — 2026-10-10

本轮完成必要返修材料与无压力独立负例。产品未修改；DeepSeek未启动、无新会话、无载荷外发。自动审批拒绝此具体载荷，等待用户明确授权该材料及既有网关，不换路由或间接执行绕过。

## 可重复的初始断言

五项为 **4 failed、1 passed、0 skipped**：build参数未收到37MiB计划限额；模拟build RSS超限被误记build_nonzero_exit；两个小规模输出例每流仅64字节、限额16字节，在hash前发现spool已64字节；低于限额并exit7的控制例通过。没有真实内存申请压力、持续输出压力、sanitizer或Range fixture。现有406输入稳定，原四项漂移修复未改动。

## 已冻结的具体载荷

仅RG01/RG02所需6段dynamic_reproduction.py、五项断言、原V01验收条目和最小失败trace；合计34007字节，SHA256 aee9134833f696a600a714010bb5b76510dd5944bf581abd52763b21d0357dd6。不含凭据、无关文件或其他项目数据。接收方为既有网关 https://st8tp3ajl0df3n8b8l8qu.apigateway-cn-beijing.volceapi.com/v1，模型deepseek-v4.1-flash；官方凭据解析、模型工具禁用、安全守卫和进程范围保持原设置。包已准备可审查，未发送。

自动审批拒绝理由：现有用户授权证据没有明确覆盖此具体私有源码/测试/日志载荷向该外部接收方的披露。父端转交的原任务返修授权不足以通过本次敏感外发检查。请求用户对此份载荷与接收方明确批准；未获回复前不重试。

## TSAN 独立环境核查

原固定镜像实际只有一个编译器GCC14.2.0；cc/gcc/gcc-14均为别名，同一libtsan.so.2.0.0，摘要d4d8d0b7b10a25c6a129e8049cff0228fa53d16d7f6f86560ad9d215402530d4。没有Clang或第二个可选编译器/runtime；不重跑已有unexpected memory mapping失败配置。

宿主只读确认Clang18.1.3及GCC13.3.0与已安装TSAN库；这不证明它们在当前获准镜像内可运行，本轮没有宿主sanitizer执行或新增挂载。镜像隔离检查全部通过，406输入稳定；0新增探针，0线程fixture执行；无ASLR/内核/capabilities/seccomp/privileged修改、安装、下载或新镜像。

## 下一步

用户明确批准该具体外发后，通过同一官方harness继续RG01/RG02补丁请求→审查→有界资源/四漂移/专项兼容复验；不削弱断言。V01不能因当前两项失败放行。V02真实TSAN继续blocked/not_run，最小需要是保持同等批准边界且已有可运行的编译器/runtime；自动生成器和CBMC不作为该选定路线新增阻碍。

全部JSON、JUnit、原日志、载荷摘要和工具链证据见同名目录。payload的process overlay/凭据引用配置不归档到项目。
