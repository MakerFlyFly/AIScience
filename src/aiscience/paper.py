"""Validate and build the canonical bilingual research paper."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .integrity import IntegrityError
from .local_cas import LocalCASIntegrityError, validate_local_cas_manifest
from .models import (
    ArtifactStatus,
    ClaimRecord,
    EvidenceCard,
    ExperimentRecord,
    ObjectRef,
    RunStatus,
    SourceRecord,
    SupportStatus,
)
from .security import redact_text
from .storage import LedgerStore

_CITATION = re.compile(r"\[[^\]]*?@([A-Za-z0-9_.:/-]+)[^\]]*?\]")
_NARRATIVE_CITATION = re.compile(r"(?<![\w@])@([A-Za-z][A-Za-z0-9_.:/-]+)")
_BIB_KEY = re.compile(r"@\w+\s*\{\s*([^,\s]+)", re.IGNORECASE)
_CLAIM_ANCHOR = re.compile(r"<!--\s*claim:([A-Za-z0-9_.:-]+)\s*-->")
_FIGURE_LINK = re.compile(r"!\[[^\]]*\]\(([^)]+)\)(?:\{#([A-Za-z0-9_.:-]+)\})?")
_FIGURE_REF = re.compile(r"@fig:([A-Za-z0-9_.:-]+)")

_USABLE_ARTIFACT_STATUSES = {ArtifactStatus.ACTIVE, ArtifactStatus.FROZEN}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git_safe_build_text(value: str, project: Path) -> str:
    """Remove secrets and local absolute paths before a build log can enter Git."""

    redacted, _ = redact_text(value)
    project_text = str(project.resolve())
    redacted = redacted.replace(project_text, "$PROJECT")
    redacted = re.sub(
        r"(?i)(?<![A-Za-z0-9])(?:[A-Z]:\\(?:[^\s\"'<>|]+\\)*[^\s\"'<>|]*)",
        "$ABSOLUTE_PATH",
        redacted,
    )
    redacted = re.sub(
        r"(?<![A-Za-z0-9])/(?:home|Users|mnt|var/tmp|tmp)/[^\s\"'<>]+",
        "$ABSOLUTE_PATH",
        redacted,
    )
    return redacted


def _git_safe_build_command(command: list[str], project: Path) -> list[str]:
    recorded: list[str] = []
    for index, argument in enumerate(command):
        normalized = _git_safe_build_text(argument, project)
        if index == 0 and Path(argument).is_absolute():
            normalized = f"$EXECUTABLE/{Path(argument).name}"
        recorded.append(normalized.replace("\\", "/"))
    return recorded


def _finding(code: str, message: str, *, severity: str = "error") -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message}


def _run_trace_identity_findings(
    store: LedgerStore, project: Path, run: ExperimentRecord
) -> list[dict[str, str]]:
    """Verify that an experiment points to one runner-owned, same-run trace bundle."""

    findings: list[dict[str, str]] = []
    expected_types = (
        ((run.plan_ref,), {"experiment.plan"}, "plan"),
        ((run.protocol_ref,), {"research.protocol"}, "protocol"),
        (run.data_refs, {"experiment.input"}, "input"),
        (run.log_refs, {"experiment.log"}, "log"),
        (
            run.artifact_refs,
            {"experiment.script", "experiment.run_record", "experiment.artifact"},
            "artifact",
        ),
    )
    for references, allowed, label in expected_types:
        for reference in references:
            if reference.object_type not in allowed:
                findings.append(
                    _finding(
                        "RUN_TRACE_TYPE_INVALID",
                        f"运行 {run.run_id} 的 {label} 引用类型无效: {reference.object_type}",
                    )
                )

    artifact_types = [reference.object_type for reference in run.artifact_refs]
    run_records = [
        reference
        for reference in run.artifact_refs
        if reference.object_type == "experiment.run_record"
    ]
    if len(run_records) != 1:
        findings.append(
            _finding(
                "RUN_RECORD_CARDINALITY_INVALID",
                f"运行 {run.run_id} 必须且只能绑定一个 run_record",
            )
        )
    if run.status is RunStatus.SUCCEEDED:
        if "experiment.script" not in artifact_types:
            findings.append(
                _finding("RUN_SCRIPT_TRACE_MISSING", f"成功运行缺少脚本绑定: {run.run_id}")
            )
        if "experiment.artifact" not in artifact_types:
            findings.append(
                _finding("RUN_OUTPUT_TRACE_MISSING", f"成功运行缺少输出绑定: {run.run_id}")
            )

    expected_root = f"runs/{run.run_id}/"
    streams: set[str] = set()
    for reference in (*run.log_refs, *run.artifact_refs):
        if reference.object_type == "experiment.script":
            continue
        try:
            trace_object = store.read_object(reference)
        except IntegrityError:
            continue
        source_path = trace_object.payload.get("source_path")
        metadata = trace_object.payload.get("metadata")
        if not isinstance(source_path, str) or not source_path.startswith(expected_root):
            findings.append(
                _finding(
                    "RUN_TRACE_IDENTITY_MISMATCH",
                    f"运行制品不属于 {run.run_id} 的 run_root: {reference.object_id}",
                )
            )
        if reference.object_type == "experiment.log":
            stream = metadata.get("stream") if isinstance(metadata, dict) else None
            if stream not in {"stdout", "stderr"}:
                findings.append(
                    _finding(
                        "RUN_LOG_IDENTITY_MISMATCH",
                        f"运行日志缺少有效 stream 身份: {run.run_id}/{reference.object_id}",
                    )
                )
            else:
                streams.add(stream)
        if reference.object_type == "experiment.run_record":
            metadata_run_id = metadata.get("run_id") if isinstance(metadata, dict) else None
            if metadata_run_id != run.run_id:
                findings.append(
                    _finding(
                        "RUN_RECORD_IDENTITY_MISMATCH",
                        f"run_record metadata 与实验 run_id 不一致: {run.run_id}",
                    )
                )
            try:
                source = (project / str(source_path)).resolve()
                source.relative_to(project.resolve())
                record = json.loads(source.read_text(encoding="utf-8"))
                expected_status = {
                    RunStatus.SUCCEEDED: "completed",
                    RunStatus.PARTIAL: "partial",
                    RunStatus.FAILED: "failed",
                }.get(run.status, run.status.value)
                if (
                    not isinstance(record, dict)
                    or record.get("run_id") != run.run_id
                    or record.get("status") != expected_status
                    or record.get("basis_commit") != run.basis_commit
                    or record.get("argv") != list(run.command)
                ):
                    raise ValueError("run identity fields differ")
            except (OSError, ValueError, json.JSONDecodeError):
                findings.append(
                    _finding(
                        "RUN_RECORD_IDENTITY_MISMATCH",
                        f"run_record 内容与实验记录不一致: {run.run_id}",
                    )
                )
    if run.status is RunStatus.SUCCEEDED and streams != {"stdout", "stderr"}:
        findings.append(
            _finding(
                "RUN_LOG_SET_INCOMPLETE",
                f"成功运行必须绑定 stdout 与 stderr: {run.run_id}",
            )
        )
    return findings


def _claim_segment(text: str, claim_id: str) -> str:
    marker = re.search(rf"<!--\s*claim:{re.escape(claim_id)}\s*-->", text)
    if marker is None:
        return ""
    next_marker = _CLAIM_ANCHOR.search(text, marker.end())
    return text[marker.end() : next_marker.start() if next_marker else len(text)]


def _normalized_prose(text: str) -> str:
    """Normalize whitespace for a conservative manuscript/ledger text binding."""

    return re.sub(r"\s+", " ", text).strip()


def _current_typed_objects(
    store: LedgerStore,
    object_type: str,
) -> tuple[tuple[ObjectRef, Any], ...]:
    """Load current usable objects of one exact type, failing closed on corruption."""

    values: list[tuple[ObjectRef, Any]] = []
    for event in store.events():
        reference = event.object_ref
        if reference is None or reference.object_type != object_type:
            continue
        ledger_object = store.read_object(reference)
        if not store.is_current_reference(reference):
            continue
        if ledger_object.status not in _USABLE_ARTIFACT_STATUSES:
            continue
        values.append((reference, ledger_object))
    return tuple(values)


def _validate_claim_ledger(
    project: Path,
    claims: list[Any],
    source_bindings: dict[str, str],
    en_text: str,
    zh_text: str,
) -> tuple[list[dict[str, str]], dict[str, list[dict[str, Any]]]]:
    """Resolve every claim/evidence/run ID to a current content-addressed object.

    The citation map is only an index.  The immutable typed ledger remains the
    authority for claim text, support state, and evidence/run dependencies.
    """

    findings: list[dict[str, str]] = []
    refs: dict[str, list[dict[str, Any]]] = {
        "claims": [],
        "evidence": [],
        "runs": [],
        "sources": [],
        "protocols": [],
    }
    try:
        store = LedgerStore(project)
        claim_objects = _current_typed_objects(store, "claim")
        evidence_objects = _current_typed_objects(store, "evidence.card")
        run_objects = _current_typed_objects(store, "experiment")
        source_objects = _current_typed_objects(store, "source")
        typed_claims = {
            ClaimRecord.model_validate(obj.payload).claim_id: (ref, obj)
            for ref, obj in claim_objects
        }
        typed_evidence = {
            EvidenceCard.model_validate(obj.payload).card_id: (ref, obj)
            for ref, obj in evidence_objects
        }
        typed_runs = {
            ExperimentRecord.model_validate(obj.payload).run_id: (ref, obj)
            for ref, obj in run_objects
        }
        typed_sources = {
            SourceRecord.model_validate(obj.payload).source_id: (ref, obj)
            for ref, obj in source_objects
        }
    except (IntegrityError, ValueError) as exc:
        return [_finding("CLAIM_LEDGER_INVALID", f"中央证据台账无效: {exc}")], refs

    used: dict[str, dict[str, ObjectRef]] = {
        "claims": {},
        "evidence": {},
        "runs": {},
        "sources": {},
        "protocols": {},
    }
    for mapped in claims:
        if not isinstance(mapped, dict) or not isinstance(mapped.get("claim_id"), str):
            continue
        claim_id = mapped["claim_id"]
        resolved = typed_claims.get(claim_id)
        if resolved is None:
            findings.append(
                _finding("CLAIM_LEDGER_MISSING", f"主张未解析到当前 ClaimRecord: {claim_id}")
            )
            continue
        claim_ref, claim_object = resolved
        claim = ClaimRecord.model_validate(claim_object.payload)
        used["claims"][claim_ref.object_id] = claim_ref
        if claim.translation_stale:
            findings.append(_finding("CLAIM_TRANSLATION_STALE", f"主张中文版本已过期: {claim_id}"))
        if mapped.get("support_status") != claim.support_status.value:
            findings.append(
                _finding("CLAIM_SUPPORT_MISMATCH", f"主张支持状态与台账不一致: {claim_id}")
            )
        mapped_evidence = mapped.get("evidence_ids", [])
        mapped_runs = mapped.get("run_ids", [])
        if not isinstance(mapped_evidence, list) or not all(
            isinstance(value, str) for value in mapped_evidence
        ):
            findings.append(_finding("CLAIM_EVIDENCE_IDS", f"主张证据 ID 无效: {claim_id}"))
            mapped_evidence = []
        if not isinstance(mapped_runs, list) or not all(
            isinstance(value, str) for value in mapped_runs
        ):
            findings.append(_finding("CLAIM_RUN_IDS", f"主张运行 ID 无效: {claim_id}"))
            mapped_runs = []
        expected_evidence = {ref.object_id for ref in claim.evidence_refs}
        expected_runs = {ref.object_id for ref in claim.run_refs}
        if set(mapped_evidence) != expected_evidence:
            findings.append(
                _finding(
                    "CLAIM_EVIDENCE_MISMATCH", f"主张证据映射与 ClaimRecord 不一致: {claim_id}"
                )
            )
        if set(mapped_runs) != expected_runs:
            findings.append(
                _finding("CLAIM_RUN_MISMATCH", f"主张运行映射与 ClaimRecord 不一致: {claim_id}")
            )
        if claim.support_status in {SupportStatus.SUPPORTED, SupportStatus.MIXED} and not (
            claim.evidence_refs or claim.run_refs
        ):
            findings.append(_finding("CLAIM_ORPHAN", f"受支持主张没有证据或运行: {claim_id}"))
        dependencies = set(claim_object.dependencies)
        expected_source_ids: set[str] = set()
        for evidence_ref in claim.evidence_refs:
            if evidence_ref not in dependencies:
                findings.append(
                    _finding("CLAIM_DEPENDENCY_MISSING", f"主张未锚定证据依赖: {claim_id}")
                )
            try:
                evidence_object = store.read_object(evidence_ref)
                evidence = EvidenceCard.model_validate(evidence_object.payload)
                if evidence_ref.object_type != "evidence.card" or not store.is_current_reference(
                    evidence_ref
                ):
                    raise ValueError("evidence reference is not current")
            except (IntegrityError, ValueError):
                findings.append(
                    _finding(
                        "EVIDENCE_LEDGER_INVALID",
                        f"主张引用的证据卡无效或已失效: {evidence_ref.object_id}",
                    )
                )
                continue
            if typed_evidence.get(evidence.card_id, (None,))[0] != evidence_ref:
                findings.append(
                    _finding("EVIDENCE_ID_MISMATCH", f"证据卡 ID/引用不一致: {evidence.card_id}")
                )
            used["evidence"][evidence_ref.object_id] = evidence_ref
            if evidence.source_ref not in set(evidence_object.dependencies):
                findings.append(
                    _finding("EVIDENCE_SOURCE_DEPENDENCY", f"证据卡未锚定来源: {evidence.card_id}")
                )
            try:
                source_object = store.read_object(evidence.source_ref)
                source = SourceRecord.model_validate(source_object.payload)
                if evidence.source_ref.object_type != "source" or not store.is_current_reference(
                    evidence.source_ref
                ):
                    raise ValueError("source reference is not current")
            except (IntegrityError, ValueError):
                findings.append(
                    _finding("SOURCE_LEDGER_INVALID", f"证据来源无效或已失效: {evidence.card_id}")
                )
            else:
                if typed_sources.get(source.source_id, (None,))[0] != evidence.source_ref:
                    findings.append(
                        _finding("SOURCE_ID_MISMATCH", f"来源 ID/引用不一致: {source.source_id}")
                    )
                if source.retracted:
                    findings.append(
                        _finding("SOURCE_RETRACTED", f"主张引用了已撤稿来源: {source.source_id}")
                    )
                used["sources"][evidence.source_ref.object_id] = evidence.source_ref
                expected_source_ids.add(source.source_id)
        claim_citations = mapped.get("citations", [])
        if isinstance(claim_citations, list) and all(
            isinstance(value, str) for value in claim_citations
        ):
            missing_bindings = sorted(set(claim_citations) - set(source_bindings))
            for key in missing_bindings:
                findings.append(
                    _finding(
                        "CLAIM_CITATION_SOURCE_UNBOUND",
                        f"主张引文没有绑定 SourceRecord: {claim_id}/{key}",
                    )
                )
            cited_source_ids = {
                source_bindings[key] for key in claim_citations if key in source_bindings
            }
            if cited_source_ids != expected_source_ids:
                findings.append(
                    _finding(
                        "CLAIM_CITATION_EVIDENCE_MISMATCH",
                        f"主张引文来源与证据卡来源不一致: {claim_id}",
                    )
                )
        for run_ref in claim.run_refs:
            if run_ref not in dependencies:
                findings.append(
                    _finding("CLAIM_DEPENDENCY_MISSING", f"主张未锚定运行依赖: {claim_id}")
                )
            try:
                run_object = store.read_object(run_ref)
                run = ExperimentRecord.model_validate(run_object.payload)
                if run_ref.object_type != "experiment" or not store.is_current_reference(run_ref):
                    raise ValueError("run reference is not current")
            except (IntegrityError, ValueError):
                findings.append(
                    _finding(
                        "RUN_LEDGER_INVALID", f"主张引用的运行无效或已失效: {run_ref.object_id}"
                    )
                )
                continue
            if typed_runs.get(run.run_id, (None,))[0] != run_ref:
                findings.append(_finding("RUN_ID_MISMATCH", f"运行 ID/引用不一致: {run.run_id}"))
            if run.status is not RunStatus.SUCCEEDED:
                findings.append(
                    _finding("RUN_NOT_SUCCEEDED", f"主张引用的运行未成功: {run.run_id}")
                )
            findings.extend(_run_trace_identity_findings(store, project, run))
            run_dependencies = set(run_object.dependencies)
            required_run_refs = {
                run.plan_ref,
                run.protocol_ref,
                *run.data_refs,
                *run.log_refs,
                *run.artifact_refs,
            }
            if not required_run_refs <= run_dependencies:
                findings.append(
                    _finding("RUN_DEPENDENCY_MISSING", f"运行依赖闭包不完整: {run.run_id}")
                )
            for trace_ref in (run.plan_ref, *run.data_refs, *run.log_refs, *run.artifact_refs):
                trace_object = None
                try:
                    if trace_ref not in run_dependencies or not store.is_current_reference(
                        trace_ref
                    ):
                        raise ValueError("trace reference is missing or superseded")
                    source_issues = store.source_binding_issues(trace_ref)
                    if source_issues:
                        raise ValueError(", ".join(source_issues))
                    trace_object = store.read_object(trace_ref)
                except (IntegrityError, ValueError) as exc:
                    findings.append(
                        _finding(
                            "RUN_TRACE_SOURCE_STALE",
                            f"运行日志或制品绑定已失效: {run.run_id}/{trace_ref.object_id}: {exc}",
                        )
                    )
                    continue
                metadata = trace_object.payload.get("metadata")
                if (
                    trace_ref.object_type in {"experiment.artifact", "experiment.log"}
                    and isinstance(metadata, dict)
                    and metadata.get("storage_policy") == "local_cas"
                ):
                    source_path = trace_object.payload.get("source_path")
                    source_sha256 = trace_object.payload.get("source_sha256")
                    if not isinstance(source_path, str) or not isinstance(source_sha256, str):
                        findings.append(
                            _finding(
                                "RUN_LOCAL_CAS_INVALID",
                                f"本地 CAS 制品绑定不完整: {run.run_id}/{trace_ref.object_id}",
                            )
                        )
                        continue
                    try:
                        validate_local_cas_manifest(
                            project,
                            project / source_path,
                            expected_manifest_sha256=source_sha256,
                        )
                    except LocalCASIntegrityError as exc:
                        findings.append(
                            _finding(
                                "RUN_LOCAL_CAS_INVALID",
                                f"本地 CAS 制品不可验证: {run.run_id}/{trace_ref.object_id}: "
                                f"{exc.code}",
                            )
                        )
            try:
                protocol_object = store.read_object(run.protocol_ref)
                if (
                    run.protocol_ref.object_type not in {"protocol", "research.protocol"}
                    or not store.is_current_reference(run.protocol_ref)
                    or protocol_object.status not in _USABLE_ARTIFACT_STATUSES
                    or protocol_object.payload.get("frozen") is not True
                ):
                    raise ValueError("protocol is not current and frozen")
                protocol_path_value = protocol_object.payload.get("source_path")
                protocol_sha256 = protocol_object.payload.get(
                    "source_sha256", protocol_object.payload.get("sha256")
                )
                if not isinstance(protocol_path_value, str) or not isinstance(
                    protocol_sha256, str
                ):
                    raise ValueError("protocol source binding is incomplete")
                protocol_path = (project / protocol_path_value).resolve()
                protocol_path.relative_to(project.resolve())
                if not protocol_path.is_file() or _sha256(protocol_path) != protocol_sha256:
                    raise ValueError("protocol source binding is stale")
            except (IntegrityError, ValueError):
                findings.append(
                    _finding(
                        "PROTOCOL_LEDGER_INVALID",
                        f"运行协议无效、已失效或未冻结: {run.protocol_ref.object_id}",
                    )
                )
            used["runs"][run_ref.object_id] = run_ref
            used["protocols"][run.protocol_ref.object_id] = run.protocol_ref
        en_segment = _normalized_prose(_claim_segment(en_text, claim_id))
        zh_segment = _normalized_prose(_claim_segment(zh_text, claim_id))
        if _normalized_prose(claim.canonical_text_en) not in en_segment:
            findings.append(
                _finding("CLAIM_TEXT_EN_MISMATCH", f"英文主张文本与台账不一致: {claim_id}")
            )
        if _normalized_prose(claim.reader_text_zh) not in zh_segment:
            findings.append(
                _finding("CLAIM_TEXT_ZH_MISMATCH", f"中文主张文本与台账不一致: {claim_id}")
            )

    for kind, mapping in used.items():
        refs[kind] = [value.model_dump(mode="json") for value in mapping.values()]
    return findings, refs


def _project_root(repo_root: Path, project_id: str) -> Path:
    projects = (Path(repo_root).resolve() / "projects").resolve()
    project = (projects / project_id).resolve()
    try:
        project.relative_to(projects)
    except ValueError as exc:
        raise ValueError("project_id 越出 projects 目录") from exc
    return project


def _validate_built_pdfs(project: Path) -> tuple[list[dict[str, str]], dict[str, Any]]:
    build = project / "paper" / "build"
    paths = {language: build / f"manuscript-{language}.pdf" for language in ("en", "zh")}
    if not any(path.exists() for path in paths.values()):
        return [], {"status": "not_present"}
    findings: list[dict[str, str]] = []
    def poppler_tool(name: str) -> str | None:
        candidates = (f"{name}.exe", name) if os.name == "nt" else (name,)
        for candidate in candidates:
            executable = shutil.which(candidate)
            if executable is None:
                continue
            try:
                probe = subprocess.run(
                    [executable, "-v"],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if probe.returncode == 0:
                return executable
        return None

    pdfinfo = poppler_tool("pdfinfo")
    pdftoppm = poppler_tool("pdftoppm")
    capabilities = {"pdfinfo": pdfinfo, "pdftoppm": pdftoppm}
    if not pdfinfo or not pdftoppm:
        findings.append(
            _finding(
                "PDF_VALIDATION_CAPABILITY_UNAVAILABLE",
                "缺少 pdfinfo 或 pdftoppm，无法验证 PDF 结构与渲染。",
            )
        )
        return findings, {"status": "capability_unavailable", **capabilities}
    for language, path in paths.items():
        if not path.is_file():
            findings.append(_finding("PDF_MISSING", f"缺少 {language} PDF。"))
            continue
        try:
            info = subprocess.run(
                [pdfinfo, str(path)],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            findings.append(
                _finding(
                    "PDF_STRUCTURE_INVALID",
                    f"{language} PDF 结构检查失败: {type(exc).__name__}",
                )
            )
            continue
        pages = re.search(r"(?m)^Pages:\s+(\d+)\s*$", info.stdout)
        if info.returncode != 0 or pages is None or int(pages.group(1)) < 1:
            findings.append(_finding("PDF_STRUCTURE_INVALID", f"{language} PDF 结构无效。"))
            continue
        try:
            with tempfile.TemporaryDirectory(prefix="aiscience-pdf-") as directory:
                prefix = Path(directory) / f"{language}-page"
                rendered = subprocess.run(
                    [pdftoppm, "-f", "1", "-l", "1", "-singlefile", "-png", str(path), str(prefix)],
                    check=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=60,
                )
                image = prefix.with_suffix(".png")
                valid_png = image.is_file() and image.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        except (OSError, subprocess.TimeoutExpired) as exc:
            findings.append(
                _finding("PDF_RENDER_INVALID", f"{language} PDF 渲染检查失败: {type(exc).__name__}")
            )
            continue
        if rendered.returncode != 0 or not valid_png:
            findings.append(_finding("PDF_RENDER_INVALID", f"{language} PDF 无法可靠渲染。"))
    return findings, {"status": "validated" if not findings else "failed", **capabilities}


def validate_paper(repo_root: Path, project_id: str) -> dict[str, Any]:
    """Mechanically validate manuscript/citation/claim/figure synchronization."""

    project = _project_root(repo_root, project_id)
    paper = project / "paper"
    en_path = paper / "en" / "manuscript.md"
    zh_path = paper / "zh" / "manuscript.md"
    bib_path = paper / "references.bib"
    map_path = paper / "citation-map.json"
    findings: list[dict[str, str]] = []
    required = (en_path, zh_path, bib_path, map_path)
    for path in required:
        if not path.is_file():
            findings.append(
                _finding("PAPER_REQUIRED_FILE", f"缺少文件: {path.relative_to(project)}")
            )
    if findings:
        return {"ok": False, "findings": findings, "stale": None}

    en_text = en_path.read_text(encoding="utf-8")
    zh_text = zh_path.read_text(encoding="utf-8")
    bib_text = bib_path.read_text(encoding="utf-8")
    try:
        citation_map = json.loads(map_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        findings.append(_finding("CITATION_MAP_JSON", f"citation-map.json 无效: {exc}"))
        return {"ok": False, "findings": findings, "stale": None}
    if not isinstance(citation_map, dict):
        findings.append(_finding("CITATION_MAP_SCHEMA", "citation-map.json 必须是对象"))
        return {"ok": False, "findings": findings, "stale": None}

    bib_keys = set(_BIB_KEY.findall(bib_text))
    en_citations = set(_CITATION.findall(en_text)) | {
        key for key in _NARRATIVE_CITATION.findall(en_text) if not key.startswith("fig:")
    }
    zh_citations = set(_CITATION.findall(zh_text)) | {
        key for key in _NARRATIVE_CITATION.findall(zh_text) if not key.startswith("fig:")
    }
    for key in sorted(en_citations | zh_citations):
        if key not in bib_keys:
            findings.append(_finding("CITATION_MISSING", f"引文键没有 BibTeX 条目: {key}"))
    raw_sources = citation_map.get("sources", [])
    source_bindings: dict[str, str] = {}
    if not isinstance(raw_sources, list):
        findings.append(_finding("CITATION_SOURCE_MAP_SCHEMA", "sources 必须是数组"))
    else:
        for binding in raw_sources:
            if (
                not isinstance(binding, dict)
                or not isinstance(binding.get("bib_key"), str)
                or not isinstance(binding.get("source_id"), str)
            ):
                findings.append(_finding("CITATION_SOURCE_MAP_SCHEMA", "来源映射字段无效"))
                continue
            key = binding["bib_key"]
            if key in source_bindings and source_bindings[key] != binding["source_id"]:
                findings.append(_finding("CITATION_SOURCE_MAP_CONFLICT", f"引文键重复绑定: {key}"))
            source_bindings[key] = binding["source_id"]
            if key not in bib_keys:
                findings.append(
                    _finding("CITATION_SOURCE_BIB_MISSING", f"来源映射缺少 BibTeX: {key}")
                )
    for key in sorted(en_citations | zh_citations):
        if key not in source_bindings:
            findings.append(
                _finding("CITATION_SOURCE_UNBOUND", f"稿件引文未绑定 SourceRecord: {key}")
            )

    actual_en_hash = _sha256(en_path)
    actual_zh_hash = _sha256(zh_path)
    mapped_hash = citation_map.get(
        "english_manuscript_sha256", citation_map.get("canonical_manuscript_sha256")
    )
    strong_zh_source_hash = citation_map.get("chinese_source_english_sha256")
    if strong_zh_source_hash is not None:
        zh_stale = (
            strong_zh_source_hash != actual_en_hash
            or citation_map.get("chinese_manuscript_sha256") != actual_zh_hash
        )
    else:
        # Compatibility with the project-template v1 map. New maps should use the stronger
        # chinese_source_english_sha256 binding because reader_status alone is a human assertion.
        reader_hash = citation_map.get("reader_manuscript_sha256")
        zh_stale = reader_hash != actual_zh_hash or citation_map.get("reader_status") != "current"
    stale = mapped_hash != actual_en_hash or zh_stale
    if mapped_hash != actual_en_hash:
        findings.append(_finding("CITATION_MAP_STALE", "citation map 未绑定当前英文权威稿"))
    if zh_stale:
        findings.append(_finding("CHINESE_STALE", "中文阅读稿未绑定当前英文权威稿"))

    en_anchors = set(_CLAIM_ANCHOR.findall(en_text))
    zh_anchors = set(_CLAIM_ANCHOR.findall(zh_text))
    claims = citation_map.get("claims", citation_map.get("entries", []))
    if not isinstance(claims, list):
        findings.append(_finding("CLAIM_MAP_SCHEMA", "claims 必须是数组"))
        claims = []
    mapped_claims: set[str] = set()
    for claim in claims:
        if not isinstance(claim, dict) or not isinstance(claim.get("claim_id"), str):
            findings.append(_finding("CLAIM_MAP_SCHEMA", "存在无 claim_id 的主张映射"))
            continue
        claim_id = claim["claim_id"]
        mapped_claims.add(claim_id)
        if claim_id not in en_anchors:
            findings.append(_finding("CLAIM_EN_ANCHOR", f"英文稿缺少主张锚点: {claim_id}"))
        if claim_id not in zh_anchors:
            findings.append(_finding("CLAIM_ZH_ANCHOR", f"中文稿缺少主张锚点: {claim_id}"))
        support = claim.get("support_status")
        if support not in {status.value for status in SupportStatus}:
            findings.append(_finding("CLAIM_SUPPORT", f"主张 {claim_id} 缺少有效支持状态"))
        if support in {
            SupportStatus.SUPPORTED.value,
            SupportStatus.REFUTED.value,
            SupportStatus.MIXED.value,
        } and not (
            claim.get("evidence_ids") or claim.get("run_ids")
        ):
            findings.append(_finding("CLAIM_ORPHAN", f"主张 {claim_id} 没有证据或运行引用"))
        citations = claim.get("citations", [])
        if not isinstance(citations, list):
            findings.append(_finding("CLAIM_CITATIONS", f"主张 {claim_id} 的 citations 必须是数组"))
        else:
            for key in citations:
                if key not in bib_keys:
                    findings.append(
                        _finding("CLAIM_CITATION_MISSING", f"主张 {claim_id} 引用了未知来源 {key}")
                    )
        numbers = claim.get("numbers", [])
        if not isinstance(numbers, list):
            findings.append(_finding("CLAIM_NUMBERS", f"主张 {claim_id} 的 numbers 必须是数组"))
        else:
            en_segment = _claim_segment(en_text, claim_id)
            zh_segment = _claim_segment(zh_text, claim_id)
            for number in numbers:
                token = str(number)
                if token not in en_segment:
                    findings.append(
                        _finding(
                            "NUMBER_EN_MISSING",
                            f"主张 {claim_id} 的数字未见于英文稿: {token}",
                        )
                    )
                if token not in zh_segment:
                    findings.append(
                        _finding(
                            "NUMBER_ZH_MISSING",
                            f"主张 {claim_id} 的数字未见于中文稿: {token}",
                        )
                    )
    for claim_id in sorted((en_anchors | zh_anchors) - mapped_claims):
        findings.append(_finding("CLAIM_UNMAPPED", f"稿件主张锚点未进入 citation map: {claim_id}"))

    ledger_findings, ledger_refs = _validate_claim_ledger(
        project,
        claims,
        source_bindings,
        en_text,
        zh_text,
    )
    findings.extend(ledger_findings)

    for language, manuscript, text in (("en", en_path, en_text), ("zh", zh_path, zh_text)):
        figure_ids: set[str] = set()
        for raw_path, figure_id in _FIGURE_LINK.findall(text):
            value = raw_path.split(maxsplit=1)[0].strip("<>")
            candidate = (manuscript.parent / value).resolve()
            try:
                candidate.relative_to(paper.resolve())
            except ValueError:
                findings.append(_finding("FIGURE_PATH", f"{language} 图路径越出 paper: {raw_path}"))
                continue
            if not candidate.is_file():
                findings.append(_finding("FIGURE_MISSING", f"{language} 图文件不存在: {raw_path}"))
            if figure_id:
                figure_ids.add(figure_id.removeprefix("fig:"))
        for figure_id in _FIGURE_REF.findall(text):
            if figure_id not in figure_ids:
                findings.append(
                    _finding("FIGURE_ANCHOR", f"{language} 图引用没有对应锚点: fig:{figure_id}")
                )

    pdf_findings, pdf_validation = _validate_built_pdfs(project)
    findings.extend(pdf_findings)

    return {
        "ok": not any(item["severity"] == "error" for item in findings),
        "findings": findings,
        "stale": stale,
        "hashes": {
            "english_manuscript": actual_en_hash,
            "chinese_manuscript": actual_zh_hash,
            "references": _sha256(bib_path),
            "citation_map": _sha256(map_path),
        },
        "citation_count": {"en": len(en_citations), "zh": len(zh_citations)},
        "claim_count": len(mapped_claims),
        "ledger_refs": ledger_refs,
        "pdf_validation": pdf_validation,
    }


def build_paper(repo_root: Path, project_id: str) -> dict[str, Any]:
    """Build English and Chinese PDFs with Pandoc/XeLaTeX after validation."""

    project = _project_root(repo_root, project_id)
    validation = validate_paper(repo_root, project_id)
    result: dict[str, Any] = {
        "status": "validation_failed" if not validation["ok"] else "pending",
        "validation": validation,
        "outputs": {},
        "capabilities": {"pandoc": shutil.which("pandoc"), "xelatex": shutil.which("xelatex")},
    }
    if not validation["ok"]:
        return result
    if not result["capabilities"]["pandoc"] or not result["capabilities"]["xelatex"]:
        result["status"] = "tool_unavailable"
        result["message"] = "需要 Pandoc 与 XeLaTeX；验证已完成但未生成 PDF"
        return result

    paper = project / "paper"
    build_dir = paper / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    failures = 0
    for language in ("en", "zh"):
        manuscript = paper / language / "manuscript.md"
        output = build_dir / f"manuscript-{language}.pdf"
        log_path = build_dir / f"{language}.log"
        command = [
            str(result["capabilities"]["pandoc"]),
            str(manuscript),
            "--from=markdown",
            "--standalone",
            "--citeproc",
            f"--bibliography={paper / 'references.bib'}",
            "--pdf-engine=xelatex",
            f"--resource-path={paper}",
            "--output",
            str(output),
        ]
        if language == "zh":
            command.extend(["--variable", "CJKmainfont=FandolSong"])
        completed = subprocess.run(
            command,
            cwd=manuscript.parent,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        log_path.write_text(
            json.dumps(
                {
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "command": _git_safe_build_command(command, project),
                    "return_code": completed.returncode,
                    "stdout": _git_safe_build_text(completed.stdout, project),
                    "stderr": _git_safe_build_text(completed.stderr, project),
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        fatal_warnings = (
            "Missing character:",
            "Could not fetch resource",
            "Citeproc:",
        )
        warning_failure = any(marker in completed.stderr for marker in fatal_warnings)
        if completed.returncode != 0 or not output.is_file() or warning_failure:
            failures += 1
            result["outputs"][language] = {
                "status": "failed",
                "log": log_path.relative_to(project).as_posix(),
                "return_code": completed.returncode,
                "fatal_warning": warning_failure,
            }
        else:
            result["outputs"][language] = {
                "status": "built",
                "path": output.relative_to(project).as_posix(),
                "sha256": _sha256(output),
                "log": log_path.relative_to(project).as_posix(),
            }
    result["status"] = "failed" if failures else "built"
    return result


__all__ = ["build_paper", "validate_paper"]
