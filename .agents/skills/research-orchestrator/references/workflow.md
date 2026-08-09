# 工作流、状态机与 Human Gate

## 状态机

规范主路径：

```text
received → charter_locked → designing ↔ literature_review
         → protocol_locked → experimenting ↔ analyzing
         → writing → reviewing → delivery_ready → delivered
```

项目可进入 `blocked`；运行或制品还可为 `failed`、`partial`、`superseded`、`withdrawn`。任何审核发现都回退到最早受影响阶段；回退不删除历史，并使受影响的下游冻结、Gate 和交付候选过期。

## 各阶段退出条件

| 阶段 | 退出证据 |
| --- | --- |
| `received` | 项目身份、负责人、初始请求已记录 |
| `charter_locked` | G0 有效，目标、范围、成功标准、约束、预算、伦理/许可、交付物明确 |
| `designing` / `literature_review` | 研究问题、假设谱系、检索记录、关键证据与反证形成闭环 |
| `protocol_locked` | 实验与分析协议、数据、环境、预算、停止条件冻结 |
| `experimenting` / `analyzing` | 运行完整登记，偏离与失败保留，预定分析和稳健性分析完成 |
| `writing` | claim ledger 覆盖实质主张，英文稿与中文稿同步 |
| `reviewing` | 证据、统计、论文和复现审核完成，高/中风险问题已处置 |
| `delivery_ready` | G2 有效且绑定最终候选 manifest |
| `delivered` | 最终包哈希与 annotated tag 已记录 |

每次转换前运行 `uv run --python 3.12 aiscience validate <project_id> --strict`。除最终 `delivered` 事实由 `package finalize` 在最终包、本地完成提交和 annotated tag 成功后写入外，只能通过 `aiscience transition` 更新中央状态；非法跳转失败关闭。

## Human Gate

### G0 研究合同

任何公开检索前请求。中文批准包至少列出目标、成功标准、范围内外、保密性、公开查询边界、数据许可与伦理、时间/运行次数/磁盘/付费/GPU预算、交付物、风险、替代方案和未决问题。预算字段不得留空；默认付费为 0、GPU 未授权、实验并发为 1。

### G1 条件执行

只有出现以下任一条件才请求：超预算，高成本或高风险，敏感数据，外部上传/通信，付费服务，不可逆动作，或所需网络/GPU/内存/文件隔离无法提供。审批只覆盖列明动作，不扩张研究范围。

### G2 主张冻结与交付

绑定英文权威稿、中文阅读稿、claim/citation map、局限、作者与 AI 披露、复现等级、交付 manifest、依赖闭包、制品 SHA-256 和 `basis_commit`。`partial` 或 `unavailable` 默认阻断；人类例外必须说明无法独立复现且进入 manifest。

## 批准有效性

批准记录包含 Gate ID、批准包路径与哈希、依赖对象的路径/版本/哈希、`basis_commit`、决定、决定者声明、UTC 时间和失效条件。依赖、制品、协议、论文或提交变化时立即标记 stale。v1 是 Git 可审计软信任，不声称人类身份经过密码学验证。

## 总控与子代理

中央台账仅允许总控经 CLI 单写。子代理只能在明确授权的唯一候选目录或 `runs/<run_id>/` 写入；不得转换状态、记录批准或改写别人的输出。并行任务上限为三个，且必须拥有不重叠输出。
