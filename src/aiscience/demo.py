"""Deterministic, network-free robust-location research demonstration."""

# ruff: noqa: E501

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import shutil
import statistics
import struct
import subprocess
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .delivery import prepare_package
from .models import (
    CapturedConfigurationValue,
    CaptureStatus,
    ClaimRecord,
    ClaimType,
    EvidenceCard,
    EvidenceRole,
    ExperimentRecord,
    GenerationTrace,
    ProtocolRecord,
    ReproductionLevel,
    ResourceControl,
    ReviewFinding,
    ReviewReportRecord,
    ReviewSeverity,
    RunStatus,
    SourceRecord,
    SupportStatus,
    generation_output_digest,
    new_id,
)
from .paper import build_paper
from .scaffold import init_project
from .storage import LedgerStore

SEED = 20260809
REPLICATES = 200
SAMPLE_SIZE = 50
CONTAMINATION = 0.10
OUTLIER_SCALE = 10.0


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8", newline="\n")


def _write_json(path: Path, value: Any) -> None:
    _write(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _simulate() -> tuple[list[dict[str, float | int]], dict[str, dict[str, float]]]:
    rng = random.Random(SEED)
    rows: list[dict[str, float | int]] = []
    for replicate in range(REPLICATES):
        sample = [
            rng.gauss(0.0, OUTLIER_SCALE if rng.random() < CONTAMINATION else 1.0)
            for _ in range(SAMPLE_SIZE)
        ]
        rows.append(
            {
                "replicate": replicate,
                "mean": statistics.fmean(sample),
                "median": statistics.median(sample),
            }
        )
    summary: dict[str, dict[str, float]] = {}
    for estimator in ("mean", "median"):
        estimates = [float(row[estimator]) for row in rows]
        summary[estimator] = {
            "bias": statistics.fmean(estimates),
            "rmse": math.sqrt(statistics.fmean(value * value for value in estimates)),
            "mae": statistics.fmean(abs(value) for value in estimates),
        }
    return rows, summary


def _write_csv(path: Path, rows: list[dict[str, float | int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=["replicate", "mean", "median"], lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(rows)


def _write_png(path: Path, summary: dict[str, dict[str, float]]) -> None:
    """Write a dependency-free RGB PNG bar chart for the PDF fixture."""

    width, height = 520, 390
    pixels = bytearray([255] * (width * height * 3))

    def rectangle(x0: int, y0: int, x1: int, y1: int, color: tuple[int, int, int]) -> None:
        for y in range(max(0, y0), min(height, y1)):
            for x in range(max(0, x0), min(width, x1)):
                offset = (y * width + x) * 3
                pixels[offset : offset + 3] = bytes(color)

    values = [summary["mean"]["rmse"], summary["median"]["rmse"]]
    maximum = max(values) * 1.15
    bar_heights = [round(240 * value / maximum) for value in values]
    rectangle(68, 58, 72, 312, (40, 40, 40))
    rectangle(68, 308, 472, 312, (40, 40, 40))
    for x, bar_height, color in zip(
        (120, 310), bar_heights, ((198, 93, 59), (40, 122, 116)), strict=True
    ):
        rectangle(x, 310 - bar_height, x + 110, 310, color)
    rectangle(115, 330, 235, 340, (198, 93, 59))
    rectangle(305, 330, 425, 340, (40, 122, 116))
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        start = y * width * 3
        rows.extend(pixels[start : start + width * 3])

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    payload = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(rows), level=9))
        + chunk(b"IEND", b"")
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _git_head(repo_root: Path) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def _experiment_script() -> str:
    return f'''"""Reproduce the offline AIScience robust-location demo."""
import csv
import json
import math
import random
import statistics
from pathlib import Path

SEED = {SEED}
REPLICATES = {REPLICATES}
N = {SAMPLE_SIZE}
EPS = {CONTAMINATION}
SCALE = {OUTLIER_SCALE}
rng = random.Random(SEED)
rows = []
for replicate in range(REPLICATES):
    sample = [
        rng.gauss(0.0, SCALE if rng.random() < EPS else 1.0)
        for _ in range(N)
    ]
    rows.append(
        {{
            "replicate": replicate,
            "mean": statistics.fmean(sample),
            "median": statistics.median(sample),
        }}
    )
summary = {{}}
for estimator in ("mean", "median"):
    values = [row[estimator] for row in rows]
    summary[estimator] = {{
        "bias": statistics.fmean(values),
        "rmse": math.sqrt(statistics.fmean(value * value for value in values)),
        "mae": statistics.fmean(abs(value) for value in values),
    }}
root = Path(__file__).resolve().parents[1]
results = root / "results"
results.mkdir(exist_ok=True)
with (results / "trials.csv").open("w", encoding="utf-8", newline="") as stream:
    writer = csv.DictWriter(
        stream, fieldnames=["replicate", "mean", "median"], lineterminator="\\n"
    )
    writer.writeheader()
    writer.writerows(rows)
(results / "summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\\n",
    encoding="utf-8",
    newline="\\n",
)
'''


def create_demo(
    repo_root: Path,
    project_id: str = "demo-robust-location",
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Create a complete deterministic demo without making any network request.

    The output is explicitly marked ``demo_only``. It prepares a candidate delivery package but
    never fabricates a human G2 approval or mixes the demonstration gate with formal delivery.
    """

    repo_root = Path(repo_root).resolve()
    projects = repo_root / "projects"
    if not project_id.startswith("demo-"):
        raise ValueError("演示 project_id 必须使用 demo- 前缀")
    project = (projects / project_id).resolve()
    try:
        project.relative_to(projects.resolve())
    except ValueError as exc:
        raise ValueError("project_id 越出 projects 目录") from exc
    if project.exists():
        if not overwrite:
            return {"status": "exists", "project_id": project_id, "path": str(project)}
        shutil.rmtree(project)
    init_result = init_project(
        repo_root,
        project_id,
        "污染正态分布下均值与中位数的位置估计稳健性比较",
        "Mean versus Median under Normal Contamination",
    )

    created_at = _utc_now()
    source_id = new_id("source")
    evidence_id = new_id("evcard")
    protocol_id = new_id("protocol")
    plan_object_id = new_id("plan")
    run_id = new_id("run")
    claim_1_id = new_id("claim")
    claim_2_id = new_id("claim")
    finding_id = new_id("finding")
    review_id = new_id("review")
    trace_id = new_id("trace")
    rows, summary = _simulate()
    mean_rmse = f"{summary['mean']['rmse']:.3f}"
    median_rmse = f"{summary['median']['rmse']:.3f}"
    reduction = f"{(1 - summary['median']['rmse'] / summary['mean']['rmse']) * 100:.1f}%"
    project_config_path = project / "project.yaml"
    project_config = yaml.safe_load(project_config_path.read_text(encoding="utf-8"))
    project_config["authors"] = ["AIScience Demo Team"]
    project_config["ai_disclosure"] = {
        "used": True,
        "en": "AI agents assisted workflow orchestration and drafting; all claims are bound to the audited local ledger.",
        "zh": "AI 代理参与了工作流编排与草拟；全部主张均绑定到已审核的本地台账。",
    }
    project_config["delivery_license_statement"] = (
        "Demo outputs: CC BY 4.0; source metadata retains its stated license."
    )
    project_config["research_contract"]["data_license_ethics"] = (
        "纯合成数据；演示输出采用 CC BY 4.0；来源元数据保留原许可。"
    )
    project_config["research_contract"].update(
        {
            "success_criteria": ["固定种子结果、双语论文、审核与候选包全部生成"],
            "scope_in": ["本地合成数据上的均值与中位数稳健性比较"],
            "scope_out": ["真实数据、联网检索、外部上传与普适优越性主张"],
            "confidentiality": "公开的纯合成演示 fixture",
            "deliverables": ["结果表", "双语论文与 PDF", "审核记录", "候选 manifest"],
            "public_query_boundary": "禁止联网；仅使用仓库内本地文献 fixture",
        }
    )
    project_config["limits"].update(
        {
            "time_hours": 0.25,
            "max_runs": 3,
            "disk_mib": 100,
            "data_scope": "synthetic_demo_only",
        }
    )
    project_config_path.write_text(
        yaml.safe_dump(project_config, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )

    _write(
        project / "README.md",
        """# 污染正态分布下位置估计的稳健性演示

这是 AIScience 的完全离线、固定种子测试项目。文献条目是测试 fixture，不代表已完成真实系统综述；所有结果仅用于验证工作流。""",
    )
    _write(
        project / "charter.md",
        f"""# G0 研究合同（演示专用）

- 标记：`demo_only`
- 问题：在 10% 重尾污染下，样本中位数是否比样本均值具有更低 RMSE？
- 成功标准：固定种子 {SEED} 下完整生成设计、运行、分析、双语稿、审核和候选交付包。
- 数据：纯合成；无个人信息、许可或伦理负担。
- 预算：付费 0，GPU 禁用，单运行，30 秒。
- 外部边界：运行期禁止网络；不上传、不投稿、不发送外部消息。
- Gate：本文件只是演示 fixture，不构成真实人类 G0/G2 批准。
""",
    )
    _write(
        project / "design" / "protocol.md",
        f"""# 冻结实验协议

从混合分布 $0.9N(0,1)+0.1N(0,{OUTLIER_SCALE}^2)$ 独立抽样。每组样本量为 {SAMPLE_SIZE}，
重复 {REPLICATES} 次，固定伪随机种子 {SEED}。比较样本均值与中位数相对真实位置 0 的偏差、MAE 和 RMSE。
主要终点是 RMSE；不进行事后终点选择或显著性检验。
""",
    )
    source_record = SourceRecord(
        source_id=source_id,
        project_id=project_id,
        title="Robust Estimation of a Location Parameter",
        doi="10.1214/aoms/1177703732",
        version_label="published-record",
        access_level="metadata_only",
        license="metadata fixture; article rights retained by publisher",
    )
    source = source_record.model_dump(mode="json")
    _write_json(project / "literature" / "fixtures" / "huber1964.json", source)
    _write(
        project / "experiments" / "robust_location.py",
        _experiment_script(),
    )
    plan = {
        "schema_version": "1.0",
        "plan_id": "robust-location",
        "demo_only": True,
        "execution_mode": "demo_fixture",
        "argv": ["python", "experiments/robust_location.py"],
        "cwd": ".",
        "timeout_seconds": 30,
        "inputs": [],
        "protocol": {
            "path": "design/protocol.md",
            "sha256": _sha256(project / "design" / "protocol.md"),
        },
        "scripts": [
            {
                "path": "experiments/robust_location.py",
                "sha256": _sha256(project / "experiments" / "robust_location.py"),
            }
        ],
        "expected_outputs": [
            {
                "path": "results/trials.csv",
                "sensitive": False,
                "redistributable": True,
            },
            {
                "path": "results/summary.json",
                "sensitive": False,
                "redistributable": True,
            },
        ],
        "environment": {"PYTHONHASHSEED": str(SEED)},
        "seeds": {"python_random": SEED},
        "resource_controls": {
            "network": "observed_only",
            "gpu": "observed_only",
            "concurrency": 1,
        },
    }
    _write_json(project / "experiments" / "plans" / "robust-location.json", plan)
    _write_csv(project / "results" / "trials.csv", rows)
    _write_json(project / "results" / "summary.json", summary)
    _write_png(project / "paper" / "figures" / "robustness.png", summary)
    run_root = project / "runs" / run_id
    _write(run_root / "logs" / "stdout.log", "deterministic in-process demo completed")
    _write(run_root / "logs" / "stderr.log", "")
    (run_root / "artifacts").mkdir(parents=True, exist_ok=True)
    shutil.copy2(project / "results" / "trials.csv", run_root / "artifacts" / "trials.csv")
    shutil.copy2(
        project / "results" / "summary.json", run_root / "artifacts" / "summary.json"
    )
    environment_sha256 = hashlib.sha256(
        json.dumps(
            {"python": "3.12", "PYTHONHASHSEED": str(SEED)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    run = {
        "schema_version": "1.0",
        "run_id": run_id,
        "plan_id": "robust-location",
        "demo_only": True,
        "status": "completed",
        "basis_commit": _git_head(repo_root),
        "argv": plan["argv"],
        "authorization": {
            "protocol": plan["protocol"],
            "scripts": plan["scripts"],
            "inputs": plan["inputs"],
        },
        "environment": {"fingerprint_sha256": environment_sha256},
        "execution": {
            "kind": "in_process_demo",
            "callable": "aiscience.demo._simulate",
            "evidence": "observed",
        },
        "reproduction_command": {
            "argv": plan["argv"],
            "shell": False,
            "evidence": "declared",
        },
        "network_used": False,
        "seeds": plan["seeds"],
        "parameters": {
            "replicates": REPLICATES,
            "sample_size": SAMPLE_SIZE,
            "contamination": CONTAMINATION,
            "outlier_scale": OUTLIER_SCALE,
        },
        "outputs": [
            {
                "path": "results/trials.csv",
                "archived_path": "artifacts/trials.csv",
                "storage_policy": "git_eligible",
                "sha256": _sha256(project / "results" / "trials.csv"),
            },
            {
                "path": "results/summary.json",
                "archived_path": "artifacts/summary.json",
                "storage_policy": "git_eligible",
                "sha256": _sha256(project / "results" / "summary.json"),
            },
        ],
        "logs": {
            "stdout": {
                "path": "logs/stdout.log",
                "storage_policy": "git_eligible",
                "sha256": _sha256(run_root / "logs" / "stdout.log"),
            },
            "stderr": {
                "path": "logs/stderr.log",
                "storage_policy": "git_eligible",
                "sha256": _sha256(run_root / "logs" / "stderr.log"),
            },
        },
        "enforcement": {
            "network": "observed_only",
            "shell_disabled": "hard",
            "filesystem_boundary": "observed_only",
        },
        "reproducibility": "full",
        "created_at": created_at,
    }
    _write_json(run_root / "run.json", run)

    claim_1_en = f"Under the pre-registered synthetic setting, the sample mean had RMSE {mean_rmse}, while the sample median had RMSE {median_rmse}; the median reduced RMSE by {reduction}."
    claim_1_zh = f"在预先固定的合成实验设定下，样本均值的 RMSE 为 {mean_rmse}，样本中位数的 RMSE 为 {median_rmse}；中位数使 RMSE 降低 {reduction}。"
    claim_2_en = "Figure 1 reports the fixed-seed result (mean at left; median at right). These values describe this simulation only and do not establish universal superiority."
    claim_2_zh = "图 1 展示固定种子结果（左侧为均值，右侧为中位数）。这些数值只描述本次模拟，不能证明中位数在所有情形下都更优。"
    en = f"""---
title: Robustness of the Mean and Median under Normal Contamination
lang: en
author: AIScience Demo Team
---

# Abstract

<!-- claim:{claim_1_id} --> {claim_1_en}

# Design

We generated {REPLICATES} samples of size {SAMPLE_SIZE} from a centered normal mixture with {CONTAMINATION:.0%} contamination. Robust estimation is motivated by classical work [@huber1964].

# Results

<!-- claim:{claim_2_id} --> {claim_2_en}

![Estimator RMSE](../figures/robustness.png){{#fig:robustness}}

# Limitations

This demo uses one distribution, one sample size, and one fixed simulation seed. The local literature record is an abstract-only test fixture, not a systematic review.

# AI Use Disclosure

AI agents assisted workflow orchestration and drafting; all claims are bound to the audited local ledger.
"""
    zh = f"""---
title: 正态污染下均值与中位数的稳健性
lang: zh-CN
author: AIScience 演示团队
---

# 摘要

<!-- claim:{claim_1_id} --> {claim_1_zh}

# 设计

我们从含 {CONTAMINATION:.0%} 污染的中心正态混合分布生成 {REPLICATES} 组样本，每组样本量为 {SAMPLE_SIZE}。经典工作为稳健估计提供了背景 [@huber1964]。

# 结果

<!-- claim:{claim_2_id} --> {claim_2_zh}

![估计量 RMSE](../figures/robustness.png){{#fig:robustness}}

# 局限

演示只使用一种分布、一个样本量和一个固定模拟种子。本地文献记录是仅含摘要级元数据的测试 fixture，不是系统综述。

# AI 使用披露

AI 代理参与了工作流编排与草拟；全部主张均绑定到已审核的本地台账。
"""
    _write(project / "paper" / "en" / "manuscript.md", en)
    _write(project / "paper" / "zh" / "manuscript.md", zh)
    _write(
        project / "paper" / "references.bib",
        """@article{huber1964,
  author = {Huber, Peter J.},
  title = {Robust Estimation of a Location Parameter},
  journal = {The Annals of Mathematical Statistics},
  year = {1964},
  volume = {35},
  number = {1},
  pages = {73--101},
  doi = {10.1214/aoms/1177703732}
}""",
    )
    en_hash = _sha256(project / "paper" / "en" / "manuscript.md")
    citation_map: dict[str, Any] = {
        "schema_version": "1.0",
        "english_manuscript_sha256": en_hash,
        "chinese_source_english_sha256": en_hash,
        "chinese_manuscript_sha256": _sha256(project / "paper" / "zh" / "manuscript.md"),
        "sources": [{"bib_key": "huber1964", "source_id": source_id}],
        "claims": [
            {
                "claim_id": claim_1_id,
                "support_status": "supported",
                "evidence_ids": [],
                "run_ids": [run_id],
                "citations": [],
                "numbers": [mean_rmse, median_rmse, reduction],
                "limitations": ["single synthetic setting", "fixed seed"],
            },
            {
                "claim_id": claim_2_id,
                "support_status": "supported",
                "evidence_ids": [evidence_id],
                "run_ids": [run_id],
                "citations": ["huber1964"],
                "numbers": [],
                "figures": ["fig:robustness"],
            },
        ],
    }
    _write_json(project / "paper" / "citation-map.json", citation_map)
    review = {
        "schema_version": "1.0",
        "review_id": review_id,
        "demo_only": True,
        "status": "passed_for_demo_candidate",
        "risk_counts": {"high": 0, "medium": 0, "low": 1},
        "findings": [
            {
                "risk": "low",
                "code": "LIMITED_EXTERNAL_VALIDITY",
                "disposition": "已在双语稿局限部分披露",
            }
        ],
        "reproducibility": "full",
    }
    _write_json(project / "reviews" / "demo-review.json", review)
    _write_json(
        project / "gates" / "DEMO-G2.json",
        {
            "schema_version": "1.0",
            "gate_id": "G2",
            "status": "demo_only_not_human_approval",
            "message_zh": "此记录仅验证模板；不得用于正式交付。",
        },
    )

    store = LedgerStore(project)
    source_ref = store.commit_object(
        project_id=project_id,
        object_type="source",
        object_id=source_id,
        payload=source_record.model_dump(mode="json"),
        event_type="literature.source_recorded",
        event_payload={"demo_only": True},
    )
    evidence = EvidenceCard(
        card_id=evidence_id,
        project_id=project_id,
        source_ref=source_ref,
        paraphrase_zh="该文献为稳健位置估计提供经典背景；演示只使用元数据，不据此提出定量结论。",
        locator="bibliographic metadata fixture",
        role=EvidenceRole.BACKGROUND,
        limitations_zh=("仅元数据级测试 fixture",),
        abstract_only=True,
    )
    evidence_ref = store.commit_object(
        project_id=project_id,
        object_type="evidence.card",
        object_id=evidence_id,
        payload=evidence.model_dump(mode="json"),
        dependencies=(source_ref,),
        event_type="evidence.card_recorded",
    )
    plan_ref = store.commit_object(
        project_id=project_id,
        object_type="experiment.plan",
        object_id=plan_object_id,
        payload={
            "source_path": "experiments/plans/robust-location.json",
            "source_sha256": _sha256(project / "experiments" / "plans" / "robust-location.json"),
            "document": plan,
            "demo_only": True,
        },
        event_type="experiment.plan_recorded",
    )
    protocol = ProtocolRecord(
        protocol_id=protocol_id,
        project_id=project_id,
        source_path="design/protocol.md",
        sha256=_sha256(project / "design" / "protocol.md"),
        frozen=True,
        demo_only=True,
    )
    protocol_ref = store.commit_object(
        project_id=project_id,
        object_type="research.protocol",
        object_id=protocol_id,
        payload=protocol.model_dump(mode="json"),
        dependencies=(source_ref,),
        event_type="research.protocol_locked",
    )
    def record_trace_artifact(
        object_type: str, source: Path, metadata: dict[str, Any]
    ) -> Any:
        return store.commit_object(
            project_id=project_id,
            object_type=object_type,
            payload={
                "source_path": source.relative_to(project).as_posix(),
                "source_sha256": _sha256(source),
                "metadata": {"run_id": run_id, **metadata},
            },
            event_type=f"{object_type}.recorded",
        )

    script_ref = record_trace_artifact(
        "experiment.script", project / "experiments" / "robust_location.py", {}
    )
    log_refs = (
        record_trace_artifact(
            "experiment.log", run_root / "logs" / "stdout.log", {"stream": "stdout"}
        ),
        record_trace_artifact(
            "experiment.log", run_root / "logs" / "stderr.log", {"stream": "stderr"}
        ),
    )
    run_record_ref = record_trace_artifact(
        "experiment.run_record", run_root / "run.json", {}
    )
    output_refs = (
        record_trace_artifact(
            "experiment.artifact", run_root / "artifacts" / "trials.csv", {"name": "trials"}
        ),
        record_trace_artifact(
            "experiment.artifact",
            run_root / "artifacts" / "summary.json",
            {"name": "summary"},
        ),
    )
    experiment = ExperimentRecord(
        run_id=run_id,
        project_id=project_id,
        plan_ref=plan_ref,
        protocol_ref=protocol_ref,
        data_refs=(),
        environment_sha256=environment_sha256,
        basis_commit=str(_git_head(repo_root)),
        command=("python", "experiments/robust_location.py"),
        seeds=(SEED,),
        hardware={"kind": "demo_fixture", "evidence": "declared"},
        status=RunStatus.SUCCEEDED,
        log_refs=log_refs,
        metrics={
            "mean_rmse": summary["mean"]["rmse"],
            "median_rmse": summary["median"]["rmse"],
        },
        artifact_refs=(script_ref, run_record_ref, *output_refs),
        resource_controls={
            "network": ResourceControl.OBSERVED_ONLY,
            "gpu": ResourceControl.OBSERVED_ONLY,
            "shell": ResourceControl.HARD,
        },
        reproduction_level=ReproductionLevel.FULL,
    )
    run_ref = store.commit_object(
        project_id=project_id,
        object_type="experiment",
        object_id=run_id,
        payload=experiment.model_dump(mode="json"),
        dependencies=(
            plan_ref,
            protocol_ref,
            script_ref,
            *log_refs,
            run_record_ref,
            *output_refs,
            source_ref,
        ),
        event_type="experiment.completed",
    )
    claim_1 = ClaimRecord(
        claim_id=claim_1_id,
        project_id=project_id,
        canonical_text_en=claim_1_en,
        reader_text_zh=claim_1_zh,
        claim_type=ClaimType.QUANTITATIVE,
        run_refs=(run_ref,),
        support_status=SupportStatus.SUPPORTED,
        limitations_zh=("单一合成设定", "固定种子"),
        canonical_version=1,
        canonical_text_sha256=hashlib.sha256(claim_1_en.encode("utf-8")).hexdigest(),
        zh_based_on_version=1,
        zh_based_on_sha256=hashlib.sha256(claim_1_en.encode("utf-8")).hexdigest(),
    )
    claim_2 = ClaimRecord(
        claim_id=claim_2_id,
        project_id=project_id,
        canonical_text_en=claim_2_en,
        reader_text_zh=claim_2_zh,
        claim_type=ClaimType.GENERALIZATION,
        evidence_refs=(evidence_ref,),
        run_refs=(run_ref,),
        support_status=SupportStatus.SUPPORTED,
        limitations_zh=("背景来源仅为元数据 fixture",),
        canonical_version=1,
        canonical_text_sha256=hashlib.sha256(claim_2_en.encode("utf-8")).hexdigest(),
        zh_based_on_version=1,
        zh_based_on_sha256=hashlib.sha256(claim_2_en.encode("utf-8")).hexdigest(),
    )
    claim_refs = (
        store.commit_object(
            project_id=project_id,
            object_type="claim",
            object_id=claim_1_id,
            payload=claim_1.model_dump(mode="json"),
            dependencies=(run_ref,),
            event_type="claim.recorded",
        ),
        store.commit_object(
            project_id=project_id,
            object_type="claim",
            object_id=claim_2_id,
            payload=claim_2.model_dump(mode="json"),
            dependencies=(evidence_ref, run_ref),
            event_type="claim.recorded",
        ),
    )
    manuscript_refs = (
        store.commit_object(
            project_id=project_id,
            object_type="writing.manuscript.en",
            payload={
                "source_path": "paper/en/manuscript.md",
                "source_sha256": _sha256(project / "paper" / "en" / "manuscript.md"),
                "text": (project / "paper" / "en" / "manuscript.md").read_text(encoding="utf-8"),
            },
            dependencies=claim_refs,
            event_type="writing.manuscript_recorded",
        ),
        store.commit_object(
            project_id=project_id,
            object_type="writing.manuscript.zh",
            payload={
                "source_path": "paper/zh/manuscript.md",
                "source_sha256": _sha256(project / "paper" / "zh" / "manuscript.md"),
                "text": (project / "paper" / "zh" / "manuscript.md").read_text(encoding="utf-8"),
            },
            dependencies=claim_refs,
            event_type="writing.manuscript_recorded",
        ),
    )
    generation_trace = GenerationTrace(
        trace_id=trace_id,
        project_id=project_id,
        role="bilingual_paper_editor",
        input_summary_redacted_zh="依据当前主张台账和固定种子运行结果生成英文权威稿与中文阅读稿。",
        instruction_commit=str(_git_head(repo_root)),
        instruction_configuration={
            "workflow": CapturedConfigurationValue(
                status=CaptureStatus.DECLARED,
                value="evidence-first bilingual drafting",
            ),
            "canonical_language": CapturedConfigurationValue(
                status=CaptureStatus.DECLARED,
                value="en",
            ),
        },
        model_configuration={
            "provider": CapturedConfigurationValue(status=CaptureStatus.UNKNOWN),
            "model": CapturedConfigurationValue(status=CaptureStatus.UNKNOWN),
            "temperature": CapturedConfigurationValue(status=CaptureStatus.UNKNOWN),
        },
        source_refs=claim_refs,
        run_refs=(run_ref,),
        tool_trace=(
            {
                "tool": "aiscience.demo",
                "action": "render_bilingual_fixture",
                "capture_status": "observed",
            },
        ),
        output_artifact_refs=manuscript_refs,
        output_sha256=generation_output_digest(manuscript_refs),
        capture_status={
            "role": CaptureStatus.DECLARED,
            "input_summary_redacted_zh": CaptureStatus.DECLARED,
            "instruction_commit": CaptureStatus.OBSERVED,
            "instruction_configuration": CaptureStatus.DECLARED,
            "model_configuration": CaptureStatus.UNKNOWN,
            "source_refs": CaptureStatus.OBSERVED,
            "run_refs": CaptureStatus.OBSERVED,
            "tool_trace": CaptureStatus.OBSERVED,
            "output_artifact_refs": CaptureStatus.OBSERVED,
            "output_sha256": CaptureStatus.OBSERVED,
        },
    )
    trace_ref = store.commit_object(
        project_id=project_id,
        object_type="generation.trace",
        object_id=trace_id,
        payload=generation_trace.model_dump(mode="json"),
        dependencies=(*claim_refs, run_ref, *manuscript_refs),
        event_type="generation.trace_recorded",
    )
    low_finding = ReviewFinding(
        finding_id=finding_id,
        project_id=project_id,
        severity=ReviewSeverity.LOW,
        category="external_validity",
        description_zh="演示仅覆盖单一合成分布与固定种子。",
        affected_refs=claim_refs,
        disposition="resolved",
        rationale_zh="已在双语稿局限部分披露。",
    )
    finding_ref = store.commit_object(
        project_id=project_id,
        object_type="review.finding",
        object_id=finding_id,
        payload=low_finding.model_dump(mode="json"),
        dependencies=claim_refs,
        event_type="review.finding_recorded",
    )
    typed_review = ReviewReportRecord(
        project_id=project_id,
        review_id=review_id,
        status="passed_for_demo_candidate",
        risk_counts={"high": 0, "medium": 0, "low": 1},
        covered_refs=(finding_ref, trace_ref, *claim_refs, run_ref, protocol_ref),
        findings=(
            {
                "risk": "low",
                "code": "LIMITED_EXTERNAL_VALIDITY",
                "disposition": "已在双语稿局限部分披露",
            },
        ),
        reproducibility=ReproductionLevel.FULL,
        demo_only=True,
    )
    review_ref = store.commit_object(
        project_id=project_id,
        object_type="review.report",
        object_id=review_id,
        payload=typed_review.model_dump(mode="json"),
        dependencies=(finding_ref, trace_ref, *claim_refs, run_ref, protocol_ref),
        event_type="review.completed",
    )
    paper_result = build_paper(repo_root, project_id)
    package_result = (
        prepare_package(repo_root, project_id, reproducibility_level="full")
        if paper_result.get("status") == "built"
        else {
            "status": "blocked",
            "findings": [
                {
                    "code": "PAPER_BUILD_INCOMPLETE",
                    "message": "双语 PDF 未全部成功构建，禁止准备候选交付包。",
                }
            ],
        }
    )
    delivery_ref = None
    if package_result.get("status") == "prepared":
        candidate_manifest = json.loads(
            (project / "delivery" / "candidate" / "manifest.json").read_text(encoding="utf-8")
        )
        delivery_ref = store.commit_object(
            project_id=project_id,
            object_type="delivery.candidate",
            payload=candidate_manifest,
            dependencies=(
                review_ref,
                finding_ref,
                trace_ref,
                *claim_refs,
                run_ref,
                protocol_ref,
            ),
            event_type="delivery.candidate_prepared",
        )
    stage_dependencies = (
        ("charter_locked", ()),
        ("designing", ()),
        ("literature_review", (source_ref, evidence_ref)),
        ("protocol_locked", (protocol_ref,)),
        ("experimenting", (plan_ref, protocol_ref)),
        ("analyzing", (run_ref,)),
        ("writing", (*claim_refs, trace_ref)),
        ("reviewing", (review_ref, finding_ref)),
    )
    previous_transition = None
    for target, dependencies in stage_dependencies:
        linked = (*dependencies, *((previous_transition,) if previous_transition else ()))
        previous_transition = store.commit_object(
            project_id=project_id,
            object_type="project.demo_transition",
            payload={"target": target, "demo_only": True, "authoritative": False},
            dependencies=linked,
            event_type="project.demo_transitioned",
            event_payload={"target": target, "demo_only": True},
        )
    if delivery_ref is not None:
        assert previous_transition is not None
        previous_transition = store.commit_object(
            project_id=project_id,
            object_type="project.demo_transition",
            payload={"target": "delivery_ready", "demo_only": True, "authoritative": False},
            dependencies=(delivery_ref, previous_transition),
            event_type="project.demo_transitioned",
            event_payload={"target": "delivery_ready", "demo_only": True},
        )
    store.commit_object(
        project_id=project_id,
        object_type="project.demo_status",
        payload={
            "status": "partial",
            "demo_only": True,
            "reason_zh": "演示流程完整，但 G2 仍待真实人类批准。",
        },
        dependencies=((previous_transition,) if previous_transition else ()),
        event_type="project.status_changed",
        event_payload={"status": "partial", "demo_only": True},
    )
    store.refresh_state_projection()
    audit = store.audit()
    return {
        "status": (
            "created"
            if paper_result.get("status") == "built" and package_result.get("status") == "prepared"
            else "partial"
        ),
        "project_id": project_id,
        "path": str(project),
        "initialization": init_result,
        "network_used": False,
        "seed": SEED,
        "metrics": summary,
        "paper": paper_result,
        "delivery": package_result,
        "delivery_ref": delivery_ref.model_dump(mode="json") if delivery_ref else None,
        "ledger_audit": audit.model_dump(mode="json"),
        "state": store.read_state(),
        "human_gate": "G2 pending; demo gate is intentionally non-authoritative",
    }


__all__ = ["create_demo"]
