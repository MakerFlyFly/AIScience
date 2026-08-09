"""Prepare and finalize allowlisted, auditable research delivery packages."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .gates import GateError, GateManager
from .integrity import IntegrityError
from .models import (
    ArtifactStatus,
    ExperimentRecord,
    GateDecision,
    GateKind,
    GateRecord,
    GenerationTrace,
    LedgerObject,
    ObjectRef,
    ReviewFinding,
    ReviewReportRecord,
    ReviewSeverity,
)
from .paper import validate_paper
from .security import scan_text
from .storage import ConcurrentWriteError, LedgerStore

Scanner = Callable[[Path, bytes], list[dict[str, str]]]

DEFAULT_ALLOWLIST = (
    "README.md",
    "charter.md",
    "design/*.md",
    "literature/fixtures/*.json",
    "experiments/*.py",
    "experiments/plans/*.json",
    "runs/*/run.json",
    "reviews/*.json",
    "paper/en/manuscript.md",
    "paper/zh/manuscript.md",
    "paper/references.bib",
    "paper/citation-map.json",
    "paper/figures/*",
    "paper/build/manuscript-en.pdf",
    "paper/build/manuscript-zh.pdf",
    "results/*.json",
    "results/*.csv",
)

_REQUIRED_DELIVERY_FILES = {
    "paper/en/manuscript.md",
    "paper/zh/manuscript.md",
    "paper/references.bib",
    "paper/citation-map.json",
    "paper/build/manuscript-en.pdf",
    "paper/build/manuscript-zh.pdf",
}
_USABLE_ARTIFACT_STATUSES = {ArtifactStatus.ACTIVE, ArtifactStatus.FROZEN}
_PACKAGE_ID = re.compile(r"pkg_[0-9a-f]{16}\Z")

_TEXT_SUFFIXES = {".bib", ".csv", ".json", ".md", ".py", ".txt", ".yaml", ".yml"}
_ABSOLUTE_PATHS = (
    re.compile(r"(?i)(?<![A-Za-z0-9])(?:[A-Z]:\\(?:[^\s\"'<>|]+\\)*[^\s\"'<>|]*)"),
    re.compile(r"(?<![A-Za-z0-9])/(?:home|Users|mnt|var/tmp|tmp)/[^\s\"'<>]+"),
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def valid_package_id(value: object) -> bool:
    """Return whether a package identifier is safe for paths and Git tag components."""

    return isinstance(value, str) and _PACKAGE_ID.fullmatch(value) is not None


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _project_root(repo_root: Path, project_id: str) -> Path:
    projects = (Path(repo_root).resolve() / "projects").resolve()
    project = (projects / project_id).resolve()
    try:
        project.relative_to(projects)
    except ValueError as exc:
        raise ValueError("project_id 越出 projects 目录") from exc
    return project


def _scan_text(path: Path, data: bytes) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [{"code": "TEXT_ENCODING", "path": path.as_posix(), "message": "文本不是 UTF-8"}]
    for finding in scan_text(text):
        # Decimal output can coincidentally contain 18 digits; it is not a PRC identifier.
        before = text[finding.start - 1] if finding.start else ""
        after = text[finding.end] if finding.end < len(text) else ""
        if finding.kind in {"PRC_ID", "PHONE"} and (before == "." or after == "."):
            continue
        findings.append(
            {
                "code": finding.kind,
                "path": path.as_posix(),
                "message": "检测到敏感内容",
            }
        )
    for pattern in _ABSOLUTE_PATHS:
        if pattern.search(text):
            findings.append(
                {"code": "ABSOLUTE_PATH", "path": path.as_posix(), "message": "检测到本地绝对路径"}
            )
            break
    if path.suffix.lower() == ".json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            findings.append(
                {"code": "INVALID_JSON", "path": path.as_posix(), "message": "JSON 无效"}
            )
        else:
            serialized = json.dumps(value, ensure_ascii=False).lower()
            restricted = '"access_level": "restricted"' in serialized
            non_redistributable = '"redistributable": false' in serialized
            if restricted or non_redistributable:
                findings.append(
                    {
                        "code": "RESTRICTED_RESOURCE",
                        "path": path.as_posix(),
                        "message": "资源不可再分发",
                    }
                )
    return findings


def _collect(project: Path, patterns: tuple[str, ...]) -> tuple[list[Path], list[dict[str, str]]]:
    files: set[Path] = set()
    findings: list[dict[str, str]] = []
    for pattern in patterns:
        candidate_pattern = Path(pattern)
        if candidate_pattern.is_absolute() or ".." in candidate_pattern.parts:
            findings.append(
                {
                    "code": "ALLOWLIST_PATH",
                    "path": pattern,
                    "message": "allowlist 只能使用项目相对路径",
                }
            )
            continue
        for path in project.glob(pattern):
            if path.is_symlink():
                findings.append(
                    {"code": "SYMLINK", "path": pattern, "message": "交付包不接受符号链接"}
                )
            elif path.is_file():
                resolved = path.resolve()
                try:
                    relative = resolved.relative_to(project.resolve())
                except ValueError:
                    findings.append(
                        {"code": "PATH_ESCAPE", "path": pattern, "message": "文件越出项目边界"}
                    )
                    continue
                if relative.parts[:2] in {("delivery", "candidate"), ("delivery", "final")}:
                    findings.append(
                        {
                            "code": "DELIVERY_RECURSION",
                            "path": relative.as_posix(),
                            "message": "候选包不能包含既有候选包或最终包",
                        }
                    )
                    continue
                files.add(resolved)
    return sorted(files), findings


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


def _git_is_ancestor(repo_root: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", ancestor, descendant],
        check=False,
        capture_output=True,
    )
    return completed.returncode == 0


def _git_path_commit(repo_root: Path, path: Path) -> str | None:
    relative = path.resolve().relative_to(repo_root.resolve()).as_posix()
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "log", "-1", "--format=%H", "--", relative],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode == 0 and completed.stdout.strip():
        return completed.stdout.strip()
    return None


def _delivery_governance(project: Path) -> dict[str, Any]:
    """Read explicit authorship, AI disclosure, and licensing declarations."""

    project_file = project / "project.yaml"
    try:
        value = yaml.safe_load(project_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(value, dict):
        return {}
    authors = value.get("authors")
    ai_disclosure = value.get("ai_disclosure")
    license_statement = value.get("delivery_license_statement")
    return {
        "authors": authors,
        "ai_disclosure": ai_disclosure,
        "license_statement": license_statement,
    }


def _governance_findings(governance: Any) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not isinstance(governance, dict):
        return [{"code": "G2_GOVERNANCE_MISSING", "message": "交付治理信息缺失"}]
    authors = governance.get("authors")
    if (
        not isinstance(authors, list)
        or not authors
        or not all(isinstance(author, str) and author.strip() for author in authors)
    ):
        findings.append({"code": "G2_AUTHORS_MISSING", "message": "缺少明确作者清单"})
    disclosure = governance.get("ai_disclosure")
    if not isinstance(disclosure, dict) or not all(
        isinstance(disclosure.get(language), str) and disclosure[language].strip()
        for language in ("en", "zh")
    ):
        findings.append({"code": "G2_AI_DISCLOSURE_MISSING", "message": "缺少中英文 AI 使用披露"})
    elif not isinstance(disclosure.get("used"), bool):
        findings.append(
            {"code": "G2_AI_USE_STATUS_MISSING", "message": "AI 使用披露缺少布尔 used 状态"}
        )
    license_statement = governance.get("license_statement")
    if (
        not isinstance(license_statement, str)
        or not license_statement.strip()
        or license_statement.strip().lower() == "unspecified"
    ):
        findings.append({"code": "G2_LICENSE_MISSING", "message": "缺少交付物许可与再分发声明"})
    return findings


def _current_objects(
    store: LedgerStore,
    object_type: str,
) -> tuple[tuple[ObjectRef, LedgerObject], ...]:
    values: list[tuple[ObjectRef, LedgerObject]] = []
    for event in store.events():
        reference = event.object_ref
        if reference is None or reference.object_type != object_type:
            continue
        ledger_object = store.read_object(reference)
        if (
            store.is_current_reference(reference)
            and ledger_object.status in _USABLE_ARTIFACT_STATUSES
        ):
            values.append((reference, ledger_object))
    return tuple(values)


def assess_delivery_readiness(
    repo_root: Path,
    project_id: str,
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the evidence/review/governance bundle that G2 must bind."""

    repo_root = Path(repo_root).resolve()
    project = _project_root(repo_root, project_id)
    findings: list[dict[str, str]] = []
    if manifest is None:
        manifest_path = project / "delivery" / "candidate" / "manifest.json"
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            loaded = None
        manifest = loaded if isinstance(loaded, dict) else None
    if not isinstance(manifest, dict):
        return {
            "ok": False,
            "findings": [{"code": "G2_MANIFEST_INVALID", "message": "候选 manifest 无效"}],
            "root_refs": [],
        }
    if not valid_package_id(manifest.get("package_id")):
        findings.append(
            {
                "code": "G2_PACKAGE_ID_INVALID",
                "message": "候选包 package_id 无效或可能导致路径越界",
            }
        )
    file_records = manifest.get("files")
    if not isinstance(file_records, list):
        findings.append({"code": "G2_MANIFEST_FILES", "message": "manifest files 无效"})
        file_records = []
    file_paths = {
        record.get("path")
        for record in file_records
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }
    for record in file_records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            continue
        relative = record["path"]
        source = (project / relative).resolve()
        try:
            source.relative_to(project)
        except ValueError:
            findings.append(
                {"code": "G2_MANIFEST_PATH_ESCAPE", "message": f"manifest 路径越界: {relative}"}
            )
            continue
        if not source.is_file() or record.get("sha256") != _sha256(source):
            findings.append(
                {
                    "code": "G2_SOURCE_MANIFEST_MISMATCH",
                    "message": f"候选 manifest 未绑定当前源制品: {relative}",
                }
            )
        if not isinstance(record.get("license"), str) or not record["license"].strip():
            findings.append(
                {"code": "G2_FILE_LICENSE_MISSING", "message": f"文件缺少许可声明: {relative}"}
            )
    for path in sorted(_REQUIRED_DELIVERY_FILES - file_paths):
        findings.append(
            {"code": "G2_REQUIRED_FILE_MISSING", "message": f"候选包缺少必需文件: {path}"}
        )
    if manifest.get("reproducibility_level") not in {
        "full",
        "local_only",
        "partial",
        "unavailable",
    }:
        findings.append({"code": "G2_REPRODUCTION_INVALID", "message": "复现等级无效"})
    findings.extend(_governance_findings(manifest.get("governance")))

    try:
        integrity = LedgerStore(project).audit()
    except (IntegrityError, ValueError) as exc:
        findings.append(
            {"code": "G2_LEDGER_INTEGRITY_FAILED", "message": f"中央台账无法审计: {exc}"}
        )
    else:
        if not integrity.ok:
            findings.append(
                {
                    "code": "G2_LEDGER_INTEGRITY_FAILED",
                    "message": "中央台账存在孤立对象、互锚异常或哈希链错误",
                }
            )

    paper_result = validate_paper(repo_root, project_id)
    for finding in paper_result.get("findings", []):
        if isinstance(finding, dict):
            findings.append(
                {
                    "code": str(finding.get("code", "PAPER_INVALID")),
                    "message": str(finding.get("message", "论文校验失败")),
                }
            )
    refs_by_kind = paper_result.get("ledger_refs", {})
    required_refs: dict[tuple[str, int], ObjectRef] = {}
    if not isinstance(refs_by_kind, dict):
        findings.append({"code": "G2_LEDGER_REFS_MISSING", "message": "论文未提供证据闭包"})
        refs_by_kind = {}
    for kind in ("claims", "evidence", "runs", "sources", "protocols"):
        raw_refs = refs_by_kind.get(kind, [])
        if not isinstance(raw_refs, list):
            findings.append({"code": "G2_LEDGER_REFS_INVALID", "message": f"{kind} 引用无效"})
            continue
        for raw_ref in raw_refs:
            try:
                reference = ObjectRef.model_validate(raw_ref)
            except ValueError:
                findings.append(
                    {"code": "G2_LEDGER_REFS_INVALID", "message": f"{kind} 含无效对象引用"}
                )
                continue
            required_refs[(reference.object_id, reference.version)] = reference
    for kind in ("claims", "runs", "protocols"):
        if not refs_by_kind.get(kind):
            findings.append({"code": "G2_REQUIRED_LEDGER_KIND", "message": f"缺少 {kind} 台账对象"})

    try:
        store = LedgerStore(project)
        level_rank = {"unavailable": 0, "partial": 1, "local_only": 2, "full": 3}
        run_levels: list[str] = []
        for raw_ref in refs_by_kind.get("runs", []):
            reference = ObjectRef.model_validate(raw_ref)
            run = ExperimentRecord.model_validate(store.read_object(reference).payload)
            run_levels.append(run.reproduction_level.value)
        manifest_level = manifest.get("reproducibility_level")
        if run_levels and isinstance(manifest_level, str):
            weakest = min(run_levels, key=level_rank.__getitem__)
            if level_rank[manifest_level] > level_rank[weakest]:
                findings.append(
                    {
                        "code": "G2_REPRODUCTION_OVERSTATED",
                        "message": (
                            f"manifest 复现等级 {manifest_level} 高于引用运行的最低等级 {weakest}"
                        ),
                    }
                )
        governance = manifest.get("governance")
        disclosure = governance.get("ai_disclosure") if isinstance(governance, dict) else None
        if isinstance(disclosure, dict) and disclosure.get("used") is True:
            trace_objects = _current_objects(store, "generation.trace")
            if not trace_objects:
                findings.append(
                    {
                        "code": "G2_GENERATION_TRACE_MISSING",
                        "message": "论文声明使用 AI/LLM，但没有当前 generation.trace",
                    }
                )
            manuscript_trace_found = False
            for trace_ref, trace_object in trace_objects:
                try:
                    trace = GenerationTrace.model_validate(trace_object.payload)
                    required_trace_dependencies = {
                        *trace.source_refs,
                        *trace.run_refs,
                        *trace.output_artifact_refs,
                    }
                    if not required_trace_dependencies <= set(trace_object.dependencies):
                        findings.append(
                            {
                                "code": "G2_TRACE_DEPENDENCY_MISSING",
                                "message": f"generation.trace 依赖闭包不完整: {trace.trace_id}",
                            }
                        )
                    if not trace.source_refs:
                        findings.append(
                            {
                                "code": "G2_TRACE_SOURCE_MISSING",
                                "message": f"generation.trace 未声明写作依据: {trace.trace_id}",
                            }
                        )
                    for reference in (*trace.source_refs, *trace.run_refs):
                        dependency_object = store.read_object(reference)
                        if (
                            not store.is_current_reference(reference)
                            or dependency_object.status not in _USABLE_ARTIFACT_STATUSES
                        ):
                            raise ValueError("trace dependency is not current")
                    output_paths: set[str] = set()
                    outputs_current = True
                    for output_ref in trace.output_artifact_refs:
                        output_object = store.read_object(output_ref)
                        if (
                            not store.is_current_reference(output_ref)
                            or output_object.status not in _USABLE_ARTIFACT_STATUSES
                        ):
                            outputs_current = False
                            continue
                        source_path = output_object.payload.get("source_path")
                        source_hash = output_object.payload.get("source_sha256")
                        if not isinstance(source_path, str) or not isinstance(source_hash, str):
                            outputs_current = False
                            continue
                        output_paths.add(source_path)
                        output_file = (project / source_path).resolve()
                        try:
                            output_file.relative_to(project)
                        except ValueError:
                            outputs_current = False
                            continue
                        if not output_file.is_file() or _sha256(output_file) != source_hash:
                            outputs_current = False
                    if not outputs_current:
                        findings.append(
                            {
                                "code": "G2_TRACE_OUTPUT_STALE",
                                "message": f"generation.trace 输出制品已失效: {trace.trace_id}",
                            }
                        )
                    if (
                        outputs_current
                        and {
                            "paper/en/manuscript.md",
                            "paper/zh/manuscript.md",
                        }
                        <= output_paths
                    ):
                        manuscript_trace_found = True
                    required_refs[(trace_ref.object_id, trace_ref.version)] = trace_ref
                    for output_ref in trace.output_artifact_refs:
                        required_refs[(output_ref.object_id, output_ref.version)] = output_ref
                except (IntegrityError, ValueError) as exc:
                    findings.append(
                        {
                            "code": "G2_GENERATION_TRACE_INVALID",
                            "message": f"generation.trace 无效: {exc}",
                        }
                    )
            if trace_objects and not manuscript_trace_found:
                findings.append(
                    {
                        "code": "G2_MANUSCRIPT_TRACE_MISSING",
                        "message": "没有 generation.trace 同时绑定当前英文和中文稿",
                    }
                )
        report_objects = _current_objects(store, "review.report")
        finding_objects = _current_objects(store, "review.finding")
        for finding_ref, finding_object in finding_objects:
            finding = ReviewFinding.model_validate(finding_object.payload)
            if finding.severity in {ReviewSeverity.HIGH, ReviewSeverity.MEDIUM} and (
                finding.disposition.strip().lower() not in {"resolved", "closed"}
            ):
                findings.append(
                    {
                        "code": "G2_REVIEW_FINDING_OPEN",
                        "message": (
                            f"存在未关闭的{finding.severity.value}风险发现: {finding.finding_id}"
                        ),
                    }
                )
            required_refs[(finding_ref.object_id, finding_ref.version)] = finding_ref
        passing_reports: list[tuple[ObjectRef, LedgerObject]] = []
        required_core = set(required_refs.values())
        for report_ref, report_object in report_objects:
            report = ReviewReportRecord.model_validate(report_object.payload)
            payload = report.model_dump(mode="json")
            counts = payload.get("risk_counts")
            status = payload.get("status")
            if (
                isinstance(counts, dict)
                and counts.get("high") == 0
                and counts.get("medium") == 0
                and status
                in (
                    {"passed_for_demo_candidate"}
                    if project_id.startswith("demo-")
                    else {"passed", "passed_for_delivery"}
                )
            ):
                closure = set(store.dependency_closure((report_ref,)))
                if required_core <= closure:
                    passing_reports.append((report_ref, report_object))
        if not passing_reports:
            findings.append(
                {
                    "code": "G2_REVIEW_NOT_CLEAN",
                    "message": "没有覆盖全部主张、协议和运行且高/中风险为 0 的当前审核报告",
                }
            )
        for report_ref, _ in passing_reports:
            required_refs[(report_ref.object_id, report_ref.version)] = report_ref
        events = store.events()
        rollback_index = next(
            (
                index
                for index in range(len(events) - 1, -1, -1)
                if events[index].event_type == "project.transitioned"
                and events[index].payload.get("rollback") is True
            ),
            None,
        )
        if rollback_index is not None:
            anchored_after = {
                event.object_ref
                for event in events[rollback_index + 1 :]
                if event.object_ref is not None
            }
            revalidated_types = {
                "claim",
                "evidence.card",
                "source",
                "protocol",
                "research.protocol",
                "experiment",
                "review.finding",
                "review.report",
            }
            stale_after_rollback = [
                reference
                for reference in required_refs.values()
                if reference.object_type in revalidated_types and reference not in anchored_after
            ]
            if stale_after_rollback:
                findings.append(
                    {
                        "code": "G2_ROLLBACK_REVALIDATION_REQUIRED",
                        "message": "工作流回退后仍引用回退前的研究或审核对象，必须生成新版本并重审",
                    }
                )
    except (IntegrityError, ValueError) as exc:
        findings.append({"code": "G2_REVIEW_LEDGER_INVALID", "message": f"审核台账无效: {exc}"})

    return {
        "ok": not findings,
        "findings": findings,
        "root_refs": [
            reference.model_dump(mode="json")
            for reference in sorted(
                required_refs.values(),
                key=lambda item: (item.object_type, item.object_id, item.version),
            )
        ],
    }


def prepare_package(
    repo_root: Path,
    project_id: str,
    *,
    allowlist: tuple[str, ...] | None = None,
    scanner: Scanner | None = None,
    reproducibility_level: str = "full",
) -> dict[str, Any]:
    """Scan and copy only explicitly allowlisted files into ``delivery/candidate``."""

    repo_root = Path(repo_root).resolve()
    project = _project_root(repo_root, project_id)
    if reproducibility_level not in {"full", "local_only", "partial", "unavailable"}:
        return {"status": "failed", "findings": [{"code": "REPRODUCIBILITY_LEVEL"}]}
    patterns = allowlist or DEFAULT_ALLOWLIST
    governance = _delivery_governance(project)
    files, findings = _collect(project, patterns)
    if not files:
        findings.append(
            {"code": "EMPTY_PACKAGE", "path": ".", "message": "allowlist 未匹配任何文件"}
        )
    records: list[dict[str, Any]] = []
    for source in files:
        relative = source.relative_to(project)
        size = source.stat().st_size
        if size > 10 * 1024 * 1024:
            findings.append(
                {
                    "code": "LARGE_FILE",
                    "path": relative.as_posix(),
                    "message": "大于 10 MiB，必须改用本地内容寻址存储并只交付 manifest",
                }
            )
            continue
        sensitive_suffixes = {".key", ".pem", ".p12", ".pfx"}
        if source.name.startswith(".env") or source.suffix.lower() in sensitive_suffixes:
            findings.append(
                {
                    "code": "SENSITIVE_FILE",
                    "path": relative.as_posix(),
                    "message": "敏感文件类型",
                }
            )
            continue
        data = source.read_bytes()
        if source.suffix.lower() in _TEXT_SUFFIXES:
            findings.extend(_scan_text(relative, data))
        if scanner is not None:
            findings.extend(scanner(relative, data))
        records.append(
            {
                "path": relative.as_posix(),
                "size_bytes": size,
                "sha256": _sha_bytes(data),
                "license": governance.get("license_statement"),
            }
        )
    if findings:
        return {"status": "blocked", "findings": findings, "file_count": len(records)}

    candidate = project / "delivery" / "candidate"
    if candidate.exists():
        shutil.rmtree(candidate)
    candidate.mkdir(parents=True)
    for record in records:
        source = project / record["path"]
        target = candidate / record["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if _sha256(target) != record["sha256"]:
            shutil.rmtree(candidate)
            return {
                "status": "failed",
                "findings": [{"code": "COPY_INTEGRITY", "path": record["path"]}],
            }

    package_digest = _sha_bytes(
        json.dumps(
            {
                "files": records,
                "governance": governance,
                "reproducibility_level": reproducibility_level,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    manifest = {
        "schema_version": "1.0",
        "project_id": project_id,
        "package_id": f"pkg_{package_digest[:16]}",
        "created_at": _utc_now(),
        "basis_commit": _git_head(repo_root),
        "reproducibility_level": reproducibility_level,
        "allowlist": list(patterns),
        "files": records,
        "governance": governance,
        "package_digest": package_digest,
    }
    manifest_path = candidate / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "status": "prepared",
        "package_id": manifest["package_id"],
        "manifest_path": manifest_path.relative_to(project).as_posix(),
        "manifest_sha256": _sha256(manifest_path),
        "basis_commit": manifest["basis_commit"],
        "reproducibility_level": reproducibility_level,
        "file_count": len(records),
        "findings": [],
    }


def g2_binding(repo_root: Path, project_id: str) -> dict[str, Any]:
    """Return the exact values a human G2 approval must bind."""

    repo_root = Path(repo_root).resolve()
    project = _project_root(repo_root, project_id)
    manifest = project / "delivery" / "candidate" / "manifest.json"
    if not manifest.is_file():
        return {"status": "unavailable", "message": "尚未准备候选交付包"}
    value = json.loads(manifest.read_text(encoding="utf-8"))
    return {
        "status": "ready",
        "gate_id": "G2",
        "candidate_manifest_sha256": _sha256(manifest),
        "basis_commit": value.get("basis_commit"),
        "package_id": value.get("package_id"),
        "reproducibility_level": value.get("reproducibility_level"),
    }


def _load_approval_path(project: Path, approval_path: Path) -> tuple[Path, ObjectRef] | None:
    candidate = approval_path if approval_path.is_absolute() else project / approval_path
    candidate = candidate.resolve()
    try:
        candidate.relative_to(project.resolve())
    except (OSError, ValueError):
        return None
    if not candidate.is_file():
        return None
    try:
        ledger_object = LedgerObject.model_validate_json(candidate.read_bytes())
        reference = ObjectRef(
            object_id=ledger_object.object_id,
            object_type=ledger_object.object_type,
            version=ledger_object.version,
            path=candidate.relative_to(project).as_posix(),
            sha256=_sha256(candidate),
        )
    except (OSError, ValueError):
        return None
    return candidate, reference


def _validate_central_g2(
    repo_root: Path,
    project: Path,
    manifest: dict[str, Any],
    manifest_path: Path,
    approval: dict[str, Any] | None,
    approval_path: Path | None,
) -> tuple[dict[str, Any] | None, str | None]:
    gate_path: Path | None = None
    if approval is not None:
        raw_ref = approval.get("gate_record_ref")
        try:
            record_ref = ObjectRef.model_validate(raw_ref)
        except ValueError:
            return None, "g2_record_ref_invalid"
    elif approval_path is not None:
        loaded = _load_approval_path(project, approval_path)
        if loaded is None:
            return None, "g2_path_invalid"
        gate_path, record_ref = loaded
    else:
        return None, "g2_missing"

    try:
        store = LedgerStore(project)
        manager = GateManager(store)
        ledger_object = store.read_object(record_ref)
        record = GateRecord.model_validate(ledger_object.payload)
        packet = manager.read_packet(record.packet_ref)
        valid, reasons = manager.validate(record_ref, current_basis_commit=record.basis_commit)
        manifest_refs = [
            reference
            for reference in record.approved_dependencies
            if reference.object_type == "delivery.manifest"
        ]
        exact_bindings = [
            reference
            for reference in manifest_refs
            if store.read_object(reference).payload.get("document") == manifest
            and store.read_object(reference).payload.get("source_sha256") == _sha256(manifest_path)
        ]
    except (ConcurrentWriteError, GateError, IntegrityError, OSError, ValueError):
        return None, "g2_ledger_invalid"
    if not valid:
        return None, "g2_ledger_stale:" + ",".join(reasons)
    if (
        record.gate is not GateKind.G2
        or packet.gate is not GateKind.G2
        or record.decision is not GateDecision.APPROVED
    ):
        return None, "g2_not_approved"
    if len(exact_bindings) != 1:
        return None, "g2_manifest_dependency_mismatch"
    if packet.reproduction_level is None or packet.reproduction_level.value != manifest.get(
        "reproducibility_level"
    ):
        return None, "g2_reproduction_level_mismatch"
    readiness = assess_delivery_readiness(
        repo_root,
        project.name,
        manifest=manifest,
    )
    if not readiness["ok"]:
        codes = ",".join(str(item.get("code")) for item in readiness["findings"])
        return None, "g2_readiness_failed:" + codes
    try:
        required_refs = {ObjectRef.model_validate(raw_ref) for raw_ref in readiness["root_refs"]}
    except ValueError:
        return None, "g2_readiness_refs_invalid"
    if not required_refs <= set(record.approved_dependencies):
        return None, "g2_evidence_closure_mismatch"

    record_path = project / record_ref.path
    record_commit = _git_path_commit(repo_root, record_path)
    current_head = _git_head(repo_root)
    if record_commit is None or record_commit != current_head:
        return None, "g2_completion_commit_mismatch"
    if gate_path is None:
        gate_path = record_path
    return (
        {
            "gate_id": record.gate.value,
            "status": record.decision.value,
            "candidate_manifest_sha256": _sha256(manifest_path),
            "basis_commit": record.basis_commit,
            "accept_limited_reproduction": record.accept_limited_reproduction,
            "gate_record_ref": record_ref.model_dump(mode="json"),
            "gate_path": gate_path,
            "validated_head": current_head,
            "dependency_hashes": approval.get("dependency_hashes", {}) if approval else {},
        },
        None,
    )


def finalize_package(
    repo_root: Path,
    project_id: str,
    *,
    approval: dict[str, Any] | None = None,
    approval_path: Path | None = None,
    create_tag: bool = True,
) -> dict[str, Any]:
    """Finalize a byte-verified candidate only when a current G2 approval binds it."""

    repo_root = Path(repo_root).resolve()
    project = _project_root(repo_root, project_id)
    candidate = project / "delivery" / "candidate"
    manifest_path = candidate / "manifest.json"
    if not manifest_path.is_file():
        return {"status": "blocked", "reason": "candidate_missing"}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"status": "blocked", "reason": "manifest_invalid", "message": str(exc)}
    if not isinstance(manifest, dict) or not valid_package_id(manifest.get("package_id")):
        return {"status": "blocked", "reason": "package_id_invalid"}
    current_manifest_hash = _sha256(manifest_path)
    gate, gate_error = _validate_central_g2(
        repo_root, project, manifest, manifest_path, approval, approval_path
    )
    if gate is None:
        required_binding = g2_binding(repo_root, project_id)
        return {
            "status": "blocked",
            "reason": gate_error,
            "required_binding": required_binding,
        }
    gate_path = gate["gate_path"]
    record_ref = gate["gate_record_ref"]
    approved_basis = gate["basis_commit"]
    current_head = gate["validated_head"]
    manifest_basis = manifest.get("basis_commit")
    basis_values = (approved_basis, manifest_basis, current_head)
    if not all(isinstance(value, str) and value for value in basis_values):
        return {"status": "blocked", "reason": "g2_basis_stale"}
    assert isinstance(approved_basis, str)
    assert isinstance(manifest_basis, str)
    assert isinstance(current_head, str)
    if not _git_is_ancestor(repo_root, approved_basis, current_head) or not _git_is_ancestor(
        repo_root, manifest_basis, approved_basis
    ):
        return {"status": "blocked", "reason": "g2_basis_stale"}
    level = manifest.get("reproducibility_level")
    accepts_limited = bool(gate["accept_limited_reproduction"])
    if level in {"partial", "unavailable"} and not accepts_limited:
        return {"status": "blocked", "reason": "limited_reproducibility_not_accepted"}

    dependencies = gate.get("dependency_hashes", {})
    if not isinstance(dependencies, dict):
        return {"status": "blocked", "reason": "g2_dependencies_invalid"}
    for relative_value, expected_hash in dependencies.items():
        if not isinstance(relative_value, str) or not isinstance(expected_hash, str):
            return {"status": "blocked", "reason": "g2_dependencies_invalid"}
        dependency = (project / relative_value).resolve()
        try:
            dependency.relative_to(project)
        except ValueError:
            return {"status": "blocked", "reason": "g2_dependency_path_escape"}
        if not dependency.is_file() or _sha256(dependency) != expected_hash:
            return {
                "status": "blocked",
                "reason": "g2_dependency_stale",
                "path": relative_value,
            }

    expected_files = {"manifest.json"}
    for record in manifest.get("files", []):
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            return {"status": "blocked", "reason": "manifest_file_invalid"}
        path = (candidate / record["path"]).resolve()
        try:
            relative = path.relative_to(candidate.resolve())
        except ValueError:
            return {"status": "blocked", "reason": "manifest_path_escape"}
        expected_files.add(relative.as_posix())
        if not path.is_file() or _sha256(path) != record.get("sha256"):
            return {"status": "blocked", "reason": "candidate_tampered", "path": record["path"]}
    actual_files: set[str] = set()
    for path in candidate.rglob("*"):
        if path.is_symlink():
            return {"status": "blocked", "reason": "candidate_symlink"}
        if path.is_file():
            actual_files.add(path.relative_to(candidate).as_posix())
    if actual_files != expected_files:
        return {"status": "blocked", "reason": "candidate_extra_or_missing_files"}
    package_id = manifest["package_id"]
    final_root = project / "delivery" / "final"
    final_path = final_root / package_id
    if final_path.exists():
        return {"status": "blocked", "reason": "final_already_exists", "package_id": package_id}
    if _git_head(repo_root) != current_head:
        return {"status": "blocked", "reason": "completion_head_changed"}
    final_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(candidate, final_path)
    if _git_head(repo_root) != current_head:
        shutil.rmtree(final_path)
        return {"status": "blocked", "reason": "completion_head_changed"}

    tag = f"aiscience-{project_id}-{package_id}"
    tag_status: dict[str, Any] = {"created": False, "name": tag}
    if create_tag:
        annotation = (
            f"Finalize {project_id} {package_id}\ncandidate_manifest_sha256={current_manifest_hash}"
        )
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "tag",
                "-a",
                tag,
                current_head,
                "-m",
                annotation,
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        tag_status = {
            "created": completed.returncode == 0,
            "name": tag,
            "error": completed.stderr.strip() or None,
        }
        if completed.returncode != 0:
            shutil.rmtree(final_path)
            return {
                "status": "failed",
                "reason": "annotated_tag_failed",
                "package_id": package_id,
                "tag": tag_status,
            }
    final_manifest = final_path / "manifest.json"
    approval_hash = (
        _sha256(gate_path)
        if gate_path is not None
        else hashlib.sha256(
            json.dumps(gate, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
    )
    return {
        "status": "finalized" if create_tag else "awaiting_completion_tag",
        "package_id": package_id,
        "final_path": final_path.relative_to(project).as_posix(),
        "manifest_sha256": _sha256(final_manifest),
        "g2_approval_sha256": approval_hash,
        "gate_record_ref": record_ref,
        "tag": tag_status,
    }


__all__ = [
    "DEFAULT_ALLOWLIST",
    "assess_delivery_readiness",
    "finalize_package",
    "g2_binding",
    "prepare_package",
    "valid_package_id",
]
