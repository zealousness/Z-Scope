# ADR-0002：有限Security Spec DSL与用户审视

- 状态：accepted-for-design
- 日期：2026-08-17
- 影响阶段：P3、P5

## 决策

SecuritySpec是版本化声明数据，不是机器学习模型或任意查询代码。编译器只接受注册表内的有限DSL。
用户通过WebUI审视scope、证据和影响，并可批准、缩小、拒绝、延后或撤销。

## 理由

有限DSL使规格可缓存、可比较、可程序校验，也避免要求用户掌握CodeQL/Joern/SVF。审阅事件和
程序事实分离，用户部署语义不会静默覆盖代码证据。

## 后果

- stable规格必须绑定用户批准或独立qualification。
- 匿名Web部署只读。
- XLSX只是审阅交换格式，JSON是规范格式。
- 旧SemanticModeler在shadow等价门禁通过后删除。
