# AIScience

AIScience 是面向计算研究的本地科研协作 OS，用 Codex 协调“接收项目 → 研究设计 → 文献 → 实验 → 分析 → 论文 → 审核 → 交付”。系统默认要求证据先行、实验可追踪、结果可复现，并只在必要决策点引入人类审批。

本项目以 [Apache License 2.0](LICENSE) 开源。公开仓库只承载框架、可再分发的测试材料和演示项目，不应存放真实研究中的密钥、个人信息、付费或受限全文、敏感数据、伦理受限输入、未公开结果或不可再分发制品。开展真实研究时，请从本模板创建独立的私有仓库；如需持续接收框架更新，可将本仓库保留为 `upstream`，并把私有仓库设为 `origin`。

公开发布可能影响专利新颖性。对可能具有专利或商业价值的新技术，应先完成专业评估和必要申请，再提交到公开仓库。Apache-2.0 的专利许可不代替专利申请或法律意见。

## 快速开始

环境固定为 Python 3.12，使用 `uv` 管理：

```powershell
uv sync --python 3.12 --locked
uv run --python 3.12 aiscience doctor
uv run --python 3.12 aiscience project init <project_id>
uv run --python 3.12 aiscience status <project_id>
```

主要命令：

```text
aiscience doctor
aiscience repo-scan [--project-id <project_id>]
aiscience project init <project_id>
aiscience status|validate|transition <project_id>
aiscience ledger record <project_id> <object_type> <source>
aiscience gate request|record <project_id>
aiscience run execute <project_id> <plan_id>
aiscience paper build <project_id>
aiscience package prepare|finalize <project_id>
aiscience demo
```

实验计划固定协议、脚本与输入哈希，但不嵌入自身所在提交的哈希；`run execute` 只在工作区干净、计划由当前 `HEAD` 跟踪，且计划、协议、脚本和输入的原始字节与 Git blob 一致时启动，并把该 `HEAD` 记录为运行的 `basis_commit`。这会拒绝只在 Git clean filter 后相等的 CRLF/LF 内容，避免记录的原始 SHA-256 在 fresh checkout 中失效；项目模板统一写入 LF。

`experiment` 规范对象不能通过通用 `ledger record` 伪造，只能由 `run execute` 在授权执行后登记。论文与 G2 还会复核日志、脚本、run record 和输出的对象类型、唯一 run record、`run_id` 及 run-root 身份。

CLI 始终输出 JSON envelope：`ok`、`command`、`project_id`、`data`、`errors`、`warnings`。错误使用稳定代码和中文说明，便于人类审阅和自动化调用。

`validate --strict` 和 `repo-scan` 会扫描 Git 已跟踪及暂存的项目文本，阻断疑似 secret、PII 和本机绝对路径。仓库提供本地 pre-commit hook；首次克隆后启用：

```powershell
git config core.hooksPath .githooks
```

`package finalize` 只接受 `delivery_ready` 状态。CLI 先构造候选完成提交与 annotated tag 对象，再用单个 Git ref transaction 原子更新当前分支和 tag；任何前置失败都会恢复 state、事件流、对象、索引与最终包目录，不留下可达的 `delivered` 事实。该命令没有跳过 tag 的公共选项，也不会推送远端。

## 目录与职责

```text
AIScience/
├─ AGENTS.md                              # 仓库级不变量
├─ .agents/skills/research-orchestrator/  # 科研状态机、协议与项目模板
├─ .codex/agents/                         # 六个专职 Custom Agents
├─ src/aiscience/                         # CLI、台账、运行与交付实现
├─ projects/<project_id>/                 # 相互隔离的研究项目
└─ tests/                                 # 单元、故障、安全与离线样例
```

项目状态由中央 CLI 单写，事件日志是追加式哈希链，规范对象按版本不可覆写。子代理只生成获授权的候选制品或独立运行目录，不能直接推进状态或批准 Gate。英文 `paper/en/manuscript.md` 是权威论文稿；中文 `paper/zh/manuscript.md` 是供人类阅读的同步稿。

## Human Gate

- **G0 研究合同**：在公开检索前确认目标、范围、数据与伦理边界、预算、成功标准和交付物。
- **G1 条件执行**：仅在超预算、高成本/风险、敏感数据、外部上传或通信、付费服务、不可逆动作、隔离不足时触发。
- **G2 主张冻结与交付**：确认双语论文、局限、作者与 AI 披露、复现等级及交付清单。

批准绑定批准包、依赖闭包、制品 SHA-256 与 `basis_commit`；依赖变化会使批准过期。v1 只提供 Git 可审计的软信任，不提供人类身份的密码学证明。

## 信任与复现边界

- 哈希链用于发现意外损坏和不一致，不能防止拥有仓库写权限的人恶意重写历史。
- 保存提示词、配置和工具轨迹只能让 LLM 产物可追踪；不能把非确定性生成宣称为确定性复现。
- Windows Job Object、超时和资源观测能力必须按 `hard`、`best_effort`、`observed_only` 如实记录；监控不等同于硬隔离。
- `partial` 或 `unavailable` 默认阻止 G2，除非人类明确接受且交付物不宣称可独立复现。
- v1 不覆盖湿实验、临床、人/动物研究、自动投稿、远程队列、容器编排、数据库或 Web UI。

## 设计来源

本项目借鉴 [The AI Scientist-v2](https://arxiv.org/abs/2504.08066) 的实验树与运行档案、[Agent Laboratory](https://aclanthology.org/2025.findings-emnlp.320/) 的端到端回退、[AI Co-Scientist](https://www.nature.com/articles/s41586-026-10644-y) 的生成—反思—排名—演化，以及 [PaperQA2](https://arxiv.org/abs/2409.13740) 的证据循环；这些仅是架构启发，不构成代码或结果兼容承诺。

Codex 载体遵循官方 [AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md.md)、[Skills](https://learn.chatgpt.com/docs/build-skills) 与 [Subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents.md) 机制。

## 验证

```powershell
uv run --python 3.12 ruff check .
uv run --python 3.12 mypy src
uv run --python 3.12 pytest
uv run --python 3.12 aiscience doctor
uv run --python 3.12 aiscience repo-scan
uv run --python 3.12 aiscience demo
```
