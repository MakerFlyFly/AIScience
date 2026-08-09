"""Repository and project scaffolding helpers."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .models import (
    AnalysisRecord,
    ClaimRecord,
    DeliveryManifest,
    EvidenceCard,
    ExperimentRecord,
    GenerationTrace,
    HypothesisRecord,
    LedgerObject,
    ObjectRef,
    ProtocolRecord,
    ReviewFinding,
    ReviewReportRecord,
    SearchRecord,
    SourceRecord,
)
from .security import assert_safe_text
from .state import ProjectState
from .storage import LedgerStore

PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")

_TYPED_PAYLOADS: dict[str, tuple[type[Any], str]] = {
    "search.record": (SearchRecord, "record_id"),
    "source": (SourceRecord, "source_id"),
    "evidence.card": (EvidenceCard, "card_id"),
    "claim": (ClaimRecord, "claim_id"),
    "hypothesis": (HypothesisRecord, "hypothesis_id"),
    "analysis": (AnalysisRecord, "analysis_id"),
    "research.protocol": (ProtocolRecord, "protocol_id"),
    "experiment": (ExperimentRecord, "run_id"),
    "review.finding": (ReviewFinding, "finding_id"),
    "review.report": (ReviewReportRecord, "review_id"),
    "generation.trace": (GenerationTrace, "trace_id"),
    "delivery.manifest": (DeliveryManifest, "manifest_id"),
}


def find_repo_root(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).resolve()
    completed = subprocess.run(
        ["git", "-C", str(current), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise RuntimeError("当前目录不在 Git 仓库中")
    return Path(completed.stdout.strip()).resolve()


def git_head(repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        raise RuntimeError("Git 仓库尚无 HEAD 提交")
    return completed.stdout.strip()


def git_is_clean(repo_root: Path) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "status", "--porcelain=v1", "--untracked-files=all"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.returncode == 0 and not completed.stdout.strip()


def load_mapping(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    assert_safe_text(text)
    value = yaml.safe_load(text) if path.suffix.lower() in {".yaml", ".yml"} else json.loads(text)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} 必须包含对象")
    return value


def init_project(repo_root: Path, project_id: str, title_zh: str, title_en: str) -> dict[str, Any]:
    if not PROJECT_ID_RE.fullmatch(project_id):
        raise ValueError("project_id 仅允许小写字母、数字、下划线和连字符")
    repo_root = repo_root.resolve()
    target = repo_root / "projects" / project_id
    if target.exists():
        raise FileExistsError(f"项目已存在: {project_id}")
    template = (
        repo_root / ".agents" / "skills" / "research-orchestrator" / "assets" / "project-template"
    )
    if not template.is_dir():
        raise FileNotFoundError("缺少 research-orchestrator 项目模板")
    shutil.copytree(template, target)
    replacements = {
        "{{PROJECT_ID}}": project_id,
        "{{TITLE_ZH}}": title_zh,
        "{{TITLE_EN}}": title_en,
        "{{CREATED_AT}}": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "{{ project_id }}": project_id,
        "{{ title_zh }}": title_zh,
        "{{ title_en }}": title_en,
        "{{ created_at_utc }}": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    for path in target.rglob("*"):
        text_suffixes = {".md", ".json", ".jsonl", ".yaml", ".yml", ".bib"}
        if path.is_file() and path.suffix.lower() in text_suffixes:
            text = path.read_text(encoding="utf-8")
            for source, replacement in replacements.items():
                text = text.replace(source, replacement)
            path.write_text(text, encoding="utf-8", newline="\n")
    project_file = target / "project.yaml"
    config = load_mapping(project_file)
    store = LedgerStore(target)
    metadata_ref = store.commit_object(
        project_id=project_id,
        object_type="project.metadata",
        payload=config,
        event_type="project.received",
        event_payload={"stage": "received"},
    )
    state = ProjectState(project_id=project_id)
    store.write_state(state.model_dump(mode="json"))
    return {
        "project_dir": target.relative_to(repo_root).as_posix(),
        "metadata_ref": metadata_ref.model_dump(mode="json"),
        "state": state.model_dump(mode="json"),
    }


def find_object_ref(project_dir: Path, object_id: str) -> ObjectRef:
    matches: list[tuple[LedgerObject, Path]] = []
    for path in (project_dir / "objects").rglob(f"{object_id}.v*.json"):
        value = LedgerObject.model_validate_json(path.read_text(encoding="utf-8"))
        matches.append((value, path))
    if not matches:
        raise FileNotFoundError(f"找不到对象: {object_id}")
    value, path = max(matches, key=lambda item: item[0].version)
    return ObjectRef(
        object_id=value.object_id,
        object_type=value.object_type,
        version=value.version,
        path=path.relative_to(project_dir).as_posix(),
        sha256=__import__("hashlib").sha256(path.read_bytes()).hexdigest(),
    )


def record_mapping(
    project_dir: Path,
    project_id: str,
    *,
    source: Path,
    object_type: str,
    dependencies: tuple[ObjectRef, ...] = (),
) -> ObjectRef:
    payload = load_mapping(source)
    store = LedgerStore(project_dir)
    return store.commit_object(
        project_id=project_id,
        object_type=object_type,
        payload=payload,
        dependencies=dependencies,
    )


def _typed_dependency_requirements(
    value: Any,
) -> tuple[tuple[ObjectRef, tuple[str, ...] | None, str], ...]:
    """Derive event-edge requirements from every typed payload ObjectRef field."""

    requirements: list[tuple[ObjectRef, tuple[str, ...] | None, str]] = []

    def add(
        references: tuple[ObjectRef, ...],
        allowed_types: tuple[str, ...] | None,
        label: str,
    ) -> None:
        requirements.extend((reference, allowed_types, label) for reference in references)

    if isinstance(value, EvidenceCard):
        add((value.source_ref,), ("source",), "source_ref")
    elif isinstance(value, ClaimRecord):
        add(value.evidence_refs, ("evidence.card",), "evidence_refs")
        add(value.run_refs, ("experiment",), "run_refs")
    elif isinstance(value, HypothesisRecord):
        add(value.parent_refs, ("hypothesis",), "parent_refs")
        add(value.evidence_refs, ("evidence.card",), "evidence_refs")
        add(value.run_refs, ("experiment",), "run_refs")
    elif isinstance(value, AnalysisRecord):
        add((value.protocol_ref,), ("research.protocol",), "protocol_ref")
        add(value.run_refs, ("experiment",), "run_refs")
    elif isinstance(value, ExperimentRecord):
        add((value.plan_ref,), ("experiment.plan",), "plan_ref")
        add((value.protocol_ref,), ("research.protocol",), "protocol_ref")
        add(value.data_refs, ("experiment.input",), "data_refs")
        add(value.log_refs, ("experiment.log",), "log_refs")
        add(
            value.artifact_refs,
            ("experiment.script", "experiment.run_record", "experiment.artifact"),
            "artifact_refs",
        )
        if value.retry_of is not None:
            add((value.retry_of,), ("experiment",), "retry_of")
    elif isinstance(value, ReviewFinding):
        add(value.affected_refs, None, "affected_refs")
    elif isinstance(value, ReviewReportRecord):
        add(value.covered_refs, None, "covered_refs")
    elif isinstance(value, GenerationTrace):
        add(value.source_refs, None, "source_refs")
        add(value.run_refs, ("experiment",), "run_refs")
        add(value.output_artifact_refs, None, "output_artifact_refs")
    elif isinstance(value, DeliveryManifest):
        add((value.gate_record_ref,), ("gate.record",), "gate_record_ref")
    return tuple(requirements)


def record_typed_payload(
    project_dir: Path,
    project_id: str,
    *,
    source: Path,
    object_type: str,
    dependencies: tuple[ObjectRef, ...] = (),
    supersedes: ObjectRef | None = None,
) -> ObjectRef:
    """Validate a canonical research payload before committing it to the ledger."""

    contract = _TYPED_PAYLOADS.get(object_type)
    if contract is None:
        raise ValueError(f"不支持的规范对象类型: {object_type}")
    model_type, identity_field = contract
    value = load_mapping(source)
    validated = model_type.model_validate(value)
    if isinstance(validated, ExperimentRecord):
        raise ValueError("experiment 只能由授权的 `aiscience run execute` 登记")
    if getattr(validated, "project_id", None) != project_id:
        raise ValueError("规范对象 project_id 与目标项目不一致")
    requirements = _typed_dependency_requirements(validated)
    missing = [reference for reference, _, _ in requirements if reference not in dependencies]
    if missing:
        missing_ids = ", ".join(sorted({reference.object_id for reference in missing}))
        raise ValueError(f"typed payload dependencies 缺少 payload 引用: {missing_ids}")
    store = LedgerStore(project_dir)
    for reference, allowed_types, label in requirements:
        store.read_object(reference)
        if not store.is_current_reference(reference):
            raise ValueError(f"{label} 引用了已失效对象: {reference.object_id}")
        if allowed_types is not None and reference.object_type not in allowed_types:
            raise ValueError(
                f"{label} 对象类型错误: {reference.object_type}; 期望 {', '.join(allowed_types)}"
            )
        if (
            isinstance(validated, GenerationTrace)
            and label == "output_artifact_refs"
            and not reference.object_type.startswith("writing.")
        ):
            raise ValueError("generation.trace 输出引用必须是 writing.* 制品")
    object_id = str(getattr(validated, identity_field))
    if supersedes is not None and (
        supersedes.object_id != object_id or supersedes.object_type != object_type
    ):
        raise ValueError("supersedes 必须指向同一对象和对象类型")
    return store.commit_object(
        project_id=project_id,
        object_type=object_type,
        object_id=object_id,
        payload=validated.model_dump(mode="json"),
        dependencies=dependencies,
        supersedes=supersedes,
        event_type=f"{object_type}.recorded",
    )


def record_artifact(
    project_dir: Path,
    project_id: str,
    *,
    source: Path,
    object_type: str,
    dependencies: tuple[ObjectRef, ...] = (),
) -> ObjectRef:
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    source_path = source.relative_to(project_dir).as_posix()
    if source.suffix.lower() in {".yaml", ".yml", ".json"}:
        payload = {
            "source_path": source_path,
            "source_sha256": source_sha256,
            "document": load_mapping(source),
        }
    else:
        text = source.read_text(encoding="utf-8")
        assert_safe_text(text)
        payload = {
            "source_path": source_path,
            "source_sha256": source_sha256,
            "text": text,
        }
    return LedgerStore(project_dir).commit_object(
        project_id=project_id,
        object_type=object_type,
        payload=payload,
        dependencies=dependencies,
    )
