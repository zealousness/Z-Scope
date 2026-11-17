# Z-SCOPE Web 看板重设计落地方案

> **历史文档，2026-11-17 归档。** 原位置：`docs/progress_docs/zscope_dashboard_redesign_implementation_plan.md`。本文保留早期导航、三栏布局及交互方案，不作为当前界面验收清单；当前接口职责见[接口与报告](../../modules/interfaces-reporting.md)，后续实际交付与待决设计见[WebUI 对照记录](../../webui-redesign/README.md)。

适用对象：Codex / 前端实现者  
目标仓库：`zealousness/Z-Scope`  
目标文件：`zscope/web/static/index.html`，必要时可新增静态 CSS/JS 文件  
参考视觉 Demo：[历史视觉稿](../../progress_docs/zscope_dashboard_redesign_demo.html)

---

## 1. 背景与目标

当前 Z-SCOPE Web 看板已经具备核心能力：

- 查看 AI 代码审计发现；
- 查看代码片段、AI 推理链、漏洞详情、验证证据；
- 对发现填写 `validation_status` 和 `validation_reasoning`；
- 回写验证结果；
- 编辑 `zscope.yaml`；
- 管理外部函数、配对函数、函数指针、函数意图等用户配置；
- 查看 CPG 状态与配置告警；
- 支持离线导出和导入。

但当前 UI 的主要问题是：

1. 信息密度过高，代码、推理、漏洞详情、验证表单堆叠在同一屏，视觉层级不够清晰。
2. 顶部操作过多，主操作「回写验证结果」不够突出。
3. 「用户配置」是表单和表格堆叠，用户难以判断哪些配置影响审计准确性。
4. Findings 列表缺少“审计优先级队列”的感觉，用户不容易快速定位高风险或待复核项。
5. 深色 glass 风格有技术感，但长期审计场景下容易造成阅读疲劳。

本次改版目标：

> 将当前页面从“技术展示型 dashboard”升级为“AI 代码审计人工复核工作台”。

核心体验原则：

- 第一眼看懂项目风险状态；
- 一屏完成发现筛选、证据查看、人工验证；
- 主操作明确：保存 / 回写验证结果；
- 配置区从“数据录入表单”升级为“分析质量健康度”；
- 尽量复用现有 Alpine.js、Tailwind、daisyUI 和后端 API，避免大规模重构。

---

## 2. 推荐信息架构

建议将页面重构为三栏审计工作台：

```text
┌────────────────────────────────────────────────────────────┐
│ 顶部导航：Z-SCOPE / 状态 / 视图切换 / 次要操作 / 主按钮       │
├───────────────┬──────────────────────────────┬─────────────┤
│ 左侧发现队列   │ 中间发现详情                  │ 右侧上下文    │
│ Findings Queue│ Evidence & Review Workspace   │ Context Rail │
│               │                              │             │
│ 搜索/筛选      │ 当前发现摘要                  │ 风险分布      │
│ 风险卡片列表    │ 代码证据                      │ CPG 状态      │
│ 状态标签        │ AI 推理链                     │ 配置健康度    │
│ 函数/位置        │ 根因/修复建议                  │ 审计流程      │
│               │ 验证状态 + 备注                │ 告警入口      │
└───────────────┴──────────────────────────────┴─────────────┘
```

### 2.1 顶部导航

保留现有能力，但重新分层：

主区域：

- Logo：`Z-SCOPE`
- 副标题：`AI 代码审计工作台`
- 版本号：来自 `/api/version`
- 在线状态：当前 `statusText`
- CPG 状态：来自 `/api/cpg_status`

主导航：

- 审计发现
- 项目配置
- 用户配置
- 告警

次要操作：

- 刷新
- 离线导出
- 导入

主操作：

- `回写验证结果`

要求：

- `回写验证结果` 必须是视觉上最突出的按钮。
- `刷新 / 离线导出 / 导入` 应弱化为 ghost / outline 按钮。
- CPG 和在线状态不要占用过多空间，可放成小型状态 pill。

---

## 3. Findings 页改版细节

### 3.1 左侧：发现队列

目标：让用户像处理审计队列一样处理 findings。

建议字段：

- `impact_level`
- `validation_status`
- `function`
- `location`
- `subcategory` / `defect_class`
- `description`
- `final_score` / `evidence_pack.final_score`

现有数据来源：

- `/api/findings?view=default`
- `/api/findings?view=with_needs_review`

保留现有视图切换：

- `Default`
- `With needs_review`

但建议 UI 文案改为：

- `默认发现`
- `包含待复核`

筛选控件建议：

- 搜索框：函数名 / 文件 / 描述 / 类别
- 状态筛选：全部、pending、needs_review、validated、rejected
- 风险筛选：critical、high、medium、low

卡片样式建议：

```text
[HIGH] [pending]                score 0.87
process_packet
src/net/packet.c:142
Potential use-after-free after error branch...
```

排序建议：

1. critical / high 优先；
2. needs_review / pending 优先；
3. score 高优先；
4. rejected / validated 靠后。

实现建议：

- 新增 computed 方法：`sortedFindings()`；
- `filteredFindings()` 之后再排序；
- 不改变后端数据结构。

---

### 3.2 中间：发现详情工作区

目标：让用户打开一个 finding 后，可以直接完成判断。

建议结构：

1. 当前发现摘要条
2. 代码证据
3. AI 推理链 / 规则证据
4. 根因与修复建议
5. 验证决策区

#### 3.2.1 当前发现摘要条

展示：

- 函数名：`selectedFinding.function`
- 位置：`selectedFinding.location`
- 风险等级：`selectedFinding.impact_level`
- 类别：`subcategory` / `defect_class`
- 规则：`rule` / `cwe`
- score：`final_score` 或 `evidence_pack.final_score`

#### 3.2.2 代码证据

继续使用 Prism 高亮。

保留字段：

- `selectedFinding.code_snippet`

建议增强：

- 代码区标题固定显示 `location`；
- 代码区保持深色背景，和浅色页面形成局部对比；
- 高度控制在 320px 到 460px；
- 支持横向滚动；
- 不要让代码区撑破整个页面。

#### 3.2.3 AI 推理链 / 证据

保留字段：

- `reasoning`
- `reasoning_process`
- `evidence_pack`
- `positive_evidence`
- `negative_evidence`
- `evidence_refs`
- `source`
- `sink`

建议拆分成两个卡片：

- `AI 推理链`
- `规则 / 证据摘要`

当前已有 `formatFindingEvidence(finding)`，建议继续复用，但视觉上从大段文本改成分组列表。

#### 3.2.4 根因与修复建议

保留字段：

- `root_cause`
- `suggested_fix`

建议用并排双卡：

```text
根本原因                         修复建议
...                              ...
```

#### 3.2.5 验证决策区

这是核心操作区。

保留字段：

- `validation_status`
- `validation_reasoning`

支持状态：

- `validated`
- `needs_review`
- `uncertain`
- `unvalidated`
- `pending`
- `rejected`

建议 UI：

- 将 select 改成 segmented button 或大型状态按钮；
- 文案保持英文值，避免影响数据一致性；
- 文本框 placeholder 改成更明确的审计提示：

```text
填写人工验证依据，例如：为什么确认为真阳性 / 为什么拒绝 / 还需要检查哪些路径。
```

保存逻辑：

- 继续复用现有 `saveFindings()`；
- 成功后不要只 `alert`，建议显示 toast；
- 失败时才使用明显错误提示。

---

## 4. 右侧上下文栏

右侧栏建议固定宽度 280px 到 340px。

包含四类模块：

### 4.1 风险分布

展示：

- Critical
- High
- Medium
- Low
- Needs review
- Pending
- Validated
- Rejected

数据来源：

- `findings`
- `viewSummary`
- `reportSummary`

可先在前端本地统计，不要求后端改动。

建议新增方法：

```js
severityCounts() {}
validationCounts() {}
```

### 4.2 CPG 状态

数据来源：

- `/api/cpg_status`
- `cpgStatus`
- `cpgError`

显示：

- ready：绿色
- building：黄色
- error：红色
- unavailable / unknown：灰色

操作：

- `构建 CPG`
- `刷新状态`

注意：

- 不要把 CPG 管理只藏在用户配置 tab 内。
- Findings 页右侧也应能看到 CPG 是否 ready，因为这直接影响分析可信度。

### 4.3 配置健康度

基于现有用户配置资源：

- `external_functions`
- `paired_functions`
- `pointer_targets`
- `function_intents`

数据来源：

- `/api/user_config/external_functions`
- `/api/user_config/paired_functions`
- `/api/user_config/pointer_targets`
- `/api/user_config/function_intents`

建议显示为：

```text
配置健康度
外部函数       12
配对函数        8
函数指针        3
函数意图        5
```

点击每一项跳转到用户配置对应 subTab。

### 4.4 审计流程提示

静态流程即可：

1. 读取高风险发现
2. 检查代码证据
3. 对照 AI 推理链
4. 填写验证结论
5. 回写结果

用途：降低新用户学习成本。

---

## 5. 用户配置页改版建议

当前用户配置页已经有外部函数、配对函数、函数指针、函数意图、CPG 管理。建议保留功能，但做视觉整理。

### 5.1 顶部增加配置说明卡

文案：

```text
用户配置会影响 Z-SCOPE 对外部函数、资源生命周期、函数指针和并发关系的理解。配置越完整，AI 审计结果越稳定。
```

### 5.2 每个配置 subTab 增加摘要

例如外部函数：

```text
外部函数：用于补充无法获取源码的库函数语义，例如 malloc、pthread_mutex_lock、自定义 SDK 函数。
当前已配置：12 项
```

### 5.3 表单收起

建议默认只展示表格和「新增」按钮；点击「新增」后展开表单。这样可以减少初始页面压迫感。

---

## 6. 告警页改版建议

当前告警页展示 `warning_type`、`context`、`message`。

建议增强：

- 按 `warning_type` 分组；
- 增加 CTA：`去补充配置`；
- 如果 warning 指向外部函数、函数指针等，可跳转到对应用户配置 subTab；
- 空状态文案改为积极反馈：

```text
暂无配置告警。当前项目配置未发现明显缺口。
```

---

## 7. 视觉规范

### 7.1 推荐主题

建议从当前纯深色 glass 主题改为浅色专业审计台：

- 页面背景：`#f6f7fb`
- 主文字：`#0f172a`
- 次级文字：`#64748b`
- 卡片背景：`#ffffff`
- 边框：`#e5e7eb`
- 主色：`#4f46e5` 或 `#2563eb`
- 危险色：`#dc2626`
- 警告色：`#d97706`
- 成功色：`#16a34a`

代码区仍建议保持深色：

- 背景：`#0f172a`
- 文字：`#d1d5db`

### 7.2 圆角与间距

- 主卡片圆角：16px
- 小标签圆角：999px
- 页面 padding：24px
- 卡片 padding：16px / 20px
- 列间距：16px / 20px

### 7.3 字体

继续使用：

- UI：Inter
- 代码：Fira Code

如不希望依赖 Google Fonts，可使用系统字体降级：

```css
font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
```

---

## 8. 技术实现建议

### 8.1 最小改动方案

保持当前架构：

- `index.html`
- Tailwind CDN
- daisyUI CDN
- Alpine.js CDN
- Prism CDN

只重构：

- `<nav>`
- Findings tab 的 HTML 结构
- 部分 CSS
- 新增若干 Alpine computed/helper 方法

不改：

- 后端 server.py API；
- report JSON 数据结构；
- 保存逻辑；
- 离线导入/导出逻辑。

### 8.2 建议新增 Alpine 方法

```js
severityWeight(level) {
  const weights = { critical: 4, high: 3, medium: 2, low: 1 };
  return weights[String(level || '').toLowerCase()] || 0;
}

validationWeight(status) {
  const weights = {
    needs_review: 5,
    pending: 4,
    uncertain: 3,
    unvalidated: 2,
    validated: 1,
    rejected: 0,
  };
  return weights[String(status || '').toLowerCase()] ?? 0;
}

findingScore(finding) {
  const score = finding.final_score ?? finding.evidence_pack?.final_score ?? 0;
  const n = Number(score);
  return Number.isFinite(n) ? n : 0;
}

sortedFindings() {
  return [...this.filteredFindings()].sort((a, b) => {
    return (
      this.severityWeight(b.impact_level) - this.severityWeight(a.impact_level) ||
      this.validationWeight(b.validation_status) - this.validationWeight(a.validation_status) ||
      this.findingScore(b) - this.findingScore(a)
    );
  });
}

countBy(field, value) {
  return this.findings.filter(item => String(item[field] || '').toLowerCase() === value).length;
}

severityCounts() {
  return {
    critical: this.countBy('impact_level', 'critical'),
    high: this.countBy('impact_level', 'high'),
    medium: this.countBy('impact_level', 'medium'),
    low: this.countBy('impact_level', 'low'),
  };
}

validationCounts() {
  return {
    needs_review: this.countBy('validation_status', 'needs_review'),
    pending: this.countBy('validation_status', 'pending'),
    validated: this.countBy('validation_status', 'validated'),
    rejected: this.countBy('validation_status', 'rejected'),
  };
}
```

### 8.3 建议修改 `saveFindings()` 交互

当前保存成功后使用 `alert`。建议改为 toast 状态：

新增状态：

```js
saveStatus: '',
saveStatusType: 'idle',
```

保存成功：

```js
this.saveStatus = '验证结果已回写';
this.saveStatusType = 'success';
```

保存失败：

```js
this.saveStatus = data.error || '回写失败';
this.saveStatusType = 'error';
```

页面右上角或底部显示 toast，3 秒后自动隐藏。

---

## 9. Codex 执行任务拆分

建议按以下任务提交，避免一次改动过大。

### Task 1：重构导航和全局视觉

目标：

- 顶部导航重新分层；
- 主按钮突出；
- 页面背景从深色改为浅色；
- 保留代码区深色。

验收：

- `/api/version` 仍能正常显示；
- `/api/cpg_status` 仍能正常轮询；
- 刷新、导入、导出、回写按钮均可用。

### Task 2：重构 Findings 三栏布局

目标：

- 左侧发现队列；
- 中间证据与验证；
- 右侧上下文栏。

验收：

- `refreshData()` 后 findings 正常展示；
- 点击 finding 后 `selectedFinding` 正常更新；
- Prism 高亮仍正常；
- `validation_status` 和 `validation_reasoning` 可编辑。

### Task 3：增加排序、统计和风险分布

目标：

- 新增 `sortedFindings()`；
- 新增 severity / validation 统计；
- 右侧显示风险分布。

验收：

- 高风险和待复核项优先显示；
- 统计数量与 findings 数组一致；
- 筛选后列表展示合理。

### Task 4：优化保存反馈

目标：

- 移除成功场景的 `alert`；
- 改成 toast；
- 错误场景显示明确失败原因。

验收：

- `/api/save_findings` 成功后显示成功提示；
- 失败后显示错误提示；
- 不阻塞用户继续操作。

### Task 5：优化用户配置页

目标：

- 增加配置健康度说明；
- 表单默认收起；
- 保留 CRUD 能力。

验收：

- 四类配置仍可加载、保存、删除；
- CPG 构建按钮仍可用；
- 配置告警仍可读取。

---

## 10. 验收标准

### 功能验收

- [ ] 页面可正常启动并访问 `http://localhost:8000`。
- [ ] `/api/findings` 数据能正常渲染。
- [ ] Default / With needs_review 视图切换正常。
- [ ] 点击 finding 可更新详情区。
- [ ] 代码片段正常高亮。
- [ ] 验证状态和验证说明可编辑。
- [ ] 回写验证结果仍调用 `/api/save_findings`。
- [ ] 项目配置 `zscope.yaml` 可加载和保存。
- [ ] 用户配置 CRUD 不回归。
- [ ] CPG 状态轮询和构建按钮不回归。
- [ ] 离线导出 / 导入不回归。

### 体验验收

- [ ] 首屏能看到风险概览。
- [ ] 主操作「回写验证结果」明确。
- [ ] 高风险 finding 更容易被发现。
- [ ] 代码证据、AI 推理链、根因、修复建议层级清楚。
- [ ] 页面不再呈现大面积拥挤的 glass 卡片。
- [ ] 用户配置页不再一打开就是大量表单压迫。

---

## 11. 不建议本阶段做的事

本阶段不建议：

- 不建议迁移到 React / Vue；
- 不建议引入复杂状态管理；
- 不建议改后端 report 数据结构；
- 不建议重写离线导出逻辑；
- 不建议做完整路由系统；
- 不建议把审计发现做成 Trello 式拖拽 Kanban。

原因：当前业务核心是审计复核，不是任务管理。最小可行改版应优先提升审计员处理单个 finding 的效率。

---

## 12. 参考视觉 Demo 说明

本方案附带的视觉 demo 文件：

```text
zscope_dashboard_redesign_demo.html
```

使用方式：

1. 直接用浏览器打开；
2. 将其作为视觉参考，不要直接替换生产 `index.html`；
3. Codex 应根据 demo 的布局和视觉风格，将现有 `index.html` 逐步重构；
4. 生产实现必须继续绑定现有 Alpine.js 状态和 API。

---

## 13. 推荐给 Codex 的一句话任务描述

```text
请基于 zscope/web/static/index.html 现有 Alpine.js + Tailwind + daisyUI 实现，将 Z-SCOPE Web 看板从深色 glass dashboard 重构为浅色三栏审计工作台。保留现有 API、数据结构、离线导入导出和配置 CRUD 能力；重点优化 Findings 页的信息架构、风险队列、代码证据展示、AI 推理链、验证决策区、右侧风险/CPG/配置健康度上下文栏，并使用 toast 替代保存成功 alert。参考 zscope_dashboard_redesign_demo.html 的视觉方向。
```
