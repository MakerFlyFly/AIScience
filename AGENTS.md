# AIScience 协作约束

- 与用户对话、Gate 审批包和供人类审阅的研究材料使用中文；英文论文是权威稿，中文稿是同步阅读稿。
- 处理科研项目时必须使用仓库技能 `research-orchestrator`，并遵循其阶段状态机与按需 references。
- 坚持 Evidence-first、Experiment-traceable、Reproducible-by-default；证据不足的内容只能标为假设、推断或不足。
- `state.json`、`ledger/` 与 Gate 记录只能由总控通过 `aiscience` CLI 写入；子代理不得直接修改中央台账，也不得替人类批准 Gate。
- 仅在必要时设置 Human Gate：G0 研究合同、条件触发的 G1、G2 主张冻结与交付。公开检索须在 G0 后；付费、上传、投稿、外部通信、敏感数据和不可逆操作不得自动执行。
- 子代理最多并行三个，只能写入明确授权的唯一候选目录或 `runs/<run_id>/`；审计代理保持只读。
- 修改后运行与风险相称的 Ruff、mypy、pytest、skill 校验和 CLI 冒烟测试。每轮完成后本地提交；不得擅自推送。
- 禁止提交密钥、令牌、PII、受限全文或不可再分发数据。超过 10 MiB 或敏感制品使用 gitignored 本地内容寻址存储，仅提交 manifest 与预期哈希。

