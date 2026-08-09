# AIScience OS v1 实现审计与处置记录

## 结论

- 最终独立只读审计基准：`28613733767a4ec754a15aa7c9140bb0bce1d5c1`
- 审计方式：新的 clean clone、固定提交、只读检查与故障注入复验
- 高风险：0
- 中风险：0
- 低风险：0（最终审计报告中的 1 项 README 滞后已在本记录所在提交一并处置）
- 演示项目 G2：保持 pending；`DEMO-G2` 不是人类批准，不得用于正式交付

## 发现与处置历史

实现期间所有独立审计轮次均未发现高风险。曾发现的中风险及处置如下：

| 范畴 | 发现 | 处置 | 状态 |
|---|---|---|---|
| 类型契约 | `SupportStatus`、typed payload 引用类型或事件依赖边可能不一致 | 统一枚举；由 typed payload 自动推导并核验引用类型与依赖边 | 已关闭 |
| 本地 CAS | manifest 可存在但 blob 缺失、篡改或 HMAC 不可验证 | SHA-256/HMAC fail-closed；验证时不创建密钥；论文/G2 复核 CAS | 已关闭 |
| 运行追踪 | 日志被忽略或 clean clone 后 source binding 失效 | 脱敏日志归档到 run-root；大/敏感日志进入本地 CAS；二次 clone 复验 | 已关闭 |
| CLI 契约 | Typer 参数错误、运行错误与退出码未完全服从 JSON envelope | 自定义 JSON group；五类稳定退出码；中文稳定错误代码 | 已关闭 |
| Gate/G2 | Gate 未绑定精确源文件、阶段或完整审核闭包 | 全 Gate 校验 source binding；G2 绑定 manifest、主张、审核、生成 trace 和状态 | 已关闭 |
| 状态投影 | schema 合法但被篡改的 `state.json` 可能被信任 | `status`、`validate`、转换和交付均要求从事件重建投影一致性 | 已关闭 |
| 回退 | rollback 后旧 G2 或旧 cutoff 仍可能被沿用 | 下游冻结、Gate 失效，并在回退后重新计算和校验 cutoff | 已关闭 |
| 生成追踪 | LLM 生成记录缺字段级观测状态、配置或输出绑定 | 结构化 `GenerationTrace`、字段级 capture status、输出对象与摘要哈希 | 已关闭 |
| Git 安全 | Git 中的 secret、PII、本机绝对路径可能漏检 | tracked/index/working-tree 扫描、strict validation 与 pre-commit hook | 已关闭 |
| PDF | 只检查文件头，截断或不可渲染 PDF 可能通过 | `pdfinfo` 结构检查和 `pdftoppm` 首页面真实渲染，能力缺失时失败关闭 | 已关闭 |
| 实验谱系 | retry 未严格指向同项目 failed/partial 前序运行 | typed `retry_of`、当前版本、项目和状态约束 | 已关闭 |
| 台账完整性 | 孤立对象或事件—对象互锚异常可能进入 G2 | G2 前执行全台账 audit，哈希链和互锚异常均阻断 | 已关闭 |
| 交付标识 | 恶意 `package_id` 可用于路径越界或非法 tag | 仅接受 `pkg_` 加 16 位小写十六进制标识；readiness 与 finalize 双重校验 | 已关闭 |
| 交付原子性 | completion commit/tag 失败可留下 delivered 事实或 final 目录 | Git plumbing 构造 commit/tag 对象，再原子更新 branch/tag refs；失败恢复 state、event、对象、index 与 final 目录 | 已关闭 |
| 实验伪造 | 通用 typed ledger 可复用任意对象或跨运行制品伪造 succeeded run | `experiment` 仅允许 runner 登记；论文/G2 再核对象类型、唯一 run record、`run_id` 和 run-root 身份 | 已关闭 |
| Windows 换行 | clean filter 可掩盖 CRLF 原始哈希与 HEAD blob 不同，fresh clone 后失效 | 启动前要求计划、协议、脚本、输入原始字节等于 HEAD blob；模板统一 LF | 已关闭 |
| 环境探测 | WindowsApps shim 或损坏命令可能被 doctor 误报为可用 | Windows 优先 `.exe`，非零退出视为 unavailable；PDF 验证工具列为必需能力 | 已关闭 |

主要修复提交为 `2569815` 与 `ad0db79`；规范演示分别在 `1f4c607` 与 `2861373` 重建。

## 最终验证证据

- `uv sync --python 3.12 --locked`：通过。
- Ruff：通过。
- mypy：19 个源码文件通过。
- pytest：137/137 通过。
- research-orchestrator skill quick validation：通过。
- `aiscience doctor`：`ready=true`。
- `aiscience repo-scan`：通过。
- 仓库演示与新建演示的 strict validation：通过。
- public `run execute`：成功；命令使用参数数组且 `shell=false`。
- 运行提交后，以 `core.autocrlf=true` 二次 clone：台账 audit 与 strict validation 通过，全部运行 source binding 无 stale，并能再次执行。
- 确定性 CSV SHA-256：`2591fe56d715b76929f50be2c59148534a734ca346eb24187dae19829a28c1ed`。
- 确定性 JSON SHA-256：`fbbbee9540bd5df1251df4ebc7d0e2e9cbdc42cfc11dca5fac02c50131bab0d9`。
- 英文 PDF SHA-256：`767a1873e68dfd3513763a02d2bbca4567c030434393033ddb577fc725095452`。
- 中文 PDF SHA-256：`2e91b44c95d202aa07e84d8d3abdd759130c904ed55d950a2f00b71640d9292f`。
- 双语 PDF 均通过结构检查；英文、中文各 2 页均完成渲染目检，无截断、重叠或乱码。

## 已知边界（非未处置缺陷）

- Git 哈希链提供一致性与意外损坏检测，不抵抗拥有仓库写权限者恶意改写历史。
- v1 不提供审批者身份的密码学证明。
- 网络、GPU、内存与文件系统边界按实际能力记录为 `hard`、`best_effort` 或 `observed_only`，不宣称不存在的硬隔离。
- LLM 产物是 `traceable_only/non_deterministic`，保存提示词和配置不等于确定性复现。
- WindowsApps 中 Codex 可执行文件的版本探测可能因系统权限显示 unavailable；这不影响仓库 CLI、Python、Git、Pandoc、XeLaTeX 与 Poppler 的 readiness。
