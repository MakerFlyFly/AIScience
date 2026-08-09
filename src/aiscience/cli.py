"""AIScience command-line interface."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any

import typer
from typer._click.exceptions import UsageError
from typer.core import TyperGroup

from .doctor import collect_doctor_report
from .envelope import ExitCode, emit, envelope, fail
from .gates import GateError, GateManager
from .integrity import IntegrityError
from .models import GateDecision, GateKind, GateRecord, ObjectRef, ProjectStage
from .run_ledger import record_experiment_run
from .scaffold import (
    find_object_ref,
    find_repo_root,
    git_head,
    git_is_clean,
    init_project,
    load_mapping,
    record_artifact,
    record_typed_payload,
)
from .state import GateState, TransitionError
from .storage import ConcurrentWriteError, LedgerStore, atomic_write

_GROUP_COMMANDS = {"gate", "ledger", "package", "paper", "project", "run"}
_RUN_INPUT_FAILURES = {"invalid_plan", "invalid_plan_id", "unsafe_environment"}
_RUN_INTEGRITY_CODES = {
    "BASIS_CHANGED_BEFORE_LAUNCH",
    "LEDGER_INTEGRITY_FAILED",
    "PROJECT_STATE_INVALID",
    "RUN_HISTORY_INVALID",
}
_RUN_UNAVAILABLE_CODES = {"GIT_HEAD_MISSING", "GIT_STATUS_UNAVAILABLE"}


def _completion_git(
    repo_root: Path, *arguments: str, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run one Git plumbing command used by the atomic delivery transaction."""

    command = ["git", "-C", str(repo_root), *arguments]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        input=input_text.encode("utf-8") if input_text is not None else None,
    )
    return subprocess.CompletedProcess(
        completed.args,
        completed.returncode,
        completed.stdout.decode("utf-8", errors="replace"),
        completed.stderr.decode("utf-8", errors="replace"),
    )


def _completed_stdout(
    completed: subprocess.CompletedProcess[str], operation: str
) -> str:
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise RuntimeError(f"{operation} failed: {detail}")
    value = completed.stdout.strip()
    if not value:
        raise RuntimeError(f"{operation} returned no value")
    return value


def _usage_context(args: Sequence[str]) -> tuple[str, str | None]:
    """Derive stable envelope identifiers without attempting a second full parse."""

    tokens = [value for value in args if not value.startswith("-")]
    if not tokens:
        return "cli", None
    command_parts = tokens[:2] if tokens[0] in _GROUP_COMMANDS and len(tokens) > 1 else tokens[:1]
    command = " ".join(command_parts)
    project_index = len(command_parts)
    project_id = tokens[project_index] if len(tokens) > project_index else None
    return command, project_id


class JsonEnvelopeGroup(TyperGroup):
    """Render Click/Typer parse failures through the public JSON contract."""

    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        windows_expand_args: bool = True,
        **extra: Any,
    ) -> Any:
        effective_args = list(sys.argv[1:] if args is None else args)
        try:
            result = super().main(
                args=effective_args,
                prog_name=prog_name,
                complete_var=complete_var,
                standalone_mode=False,
                windows_expand_args=windows_expand_args,
                **extra,
            )
        except UsageError as exc:
            command, project_id = _usage_context(effective_args)
            emit(
                envelope(
                    ok=False,
                    command=command,
                    project_id=project_id,
                    errors=[
                        {
                            "code": "CLI_USAGE_ERROR",
                            "message_zh": f"命令参数无效：{exc.format_message()}",
                            "details": {},
                        }
                    ],
                )
            )
            result = int(ExitCode.INPUT)
        if standalone_mode:
            raise SystemExit(result if isinstance(result, int) else 0)
        return result


def _run_failure_exit_code(result: dict[str, Any]) -> ExitCode:
    """Map runner facts to the five stable public exit classes."""

    status = result.get("status")
    failure = str(result.get("failure_kind") or "")
    error_code = str(result.get("error_code") or "")
    if (
        status == "input_unavailable"
        or failure == "launch"
        or error_code in _RUN_UNAVAILABLE_CODES
    ):
        return ExitCode.UNAVAILABLE
    if failure == "concurrent_run" or error_code in _RUN_INTEGRITY_CODES:
        return ExitCode.INTEGRITY
    if failure in _RUN_INPUT_FAILURES or error_code.startswith(("PLAN_", "PROJECT_CONTRACT_")):
        return ExitCode.INPUT
    if error_code in {
        "EXECUTION_MODE_INVALID",
        "PROJECT_DEFAULT_MISSING",
        "PROJECT_DEFAULTS_MISSING",
        "PROJECT_LIMIT_INVALID",
        "PROJECT_LIMIT_MISSING",
        "PROJECT_LIMITS_MISSING",
    }:
        return ExitCode.INPUT
    return ExitCode.PRECONDITION


app = typer.Typer(
    cls=JsonEnvelopeGroup,
    no_args_is_help=True,
    help="AIScience 科研协作 OS",
    pretty_exceptions_enable=False,
)
project_app = typer.Typer(no_args_is_help=True, help="项目管理")
gate_app = typer.Typer(no_args_is_help=True, help="Human Gate 管理")
run_app = typer.Typer(no_args_is_help=True, help="实验运行")
paper_app = typer.Typer(no_args_is_help=True, help="双语论文")
package_app = typer.Typer(no_args_is_help=True, help="交付包")
ledger_app = typer.Typer(no_args_is_help=True, help="规范科研对象台账")
app.add_typer(project_app, name="project")
app.add_typer(gate_app, name="gate")
app.add_typer(run_app, name="run")
app.add_typer(paper_app, name="paper")
app.add_typer(package_app, name="package")
app.add_typer(ledger_app, name="ledger")


def _repo() -> Path:
    try:
        return find_repo_root()
    except RuntimeError as exc:
        fail(
            command="repository",
            code="NOT_GIT_REPOSITORY",
            message_zh=str(exc),
            exit_code=ExitCode.UNAVAILABLE,
        )


def _project(repo_root: Path, project_id: str) -> Path:
    project = (repo_root / "projects" / project_id).resolve()
    try:
        project.relative_to((repo_root / "projects").resolve())
    except ValueError:
        fail(
            command="project",
            code="PROJECT_PATH_ESCAPE",
            message_zh="project_id 越出 projects 目录。",
            exit_code=ExitCode.INPUT,
            project_id=project_id,
        )
    if not project.is_dir():
        fail(
            command="project",
            code="PROJECT_NOT_FOUND",
            message_zh="项目不存在。",
            exit_code=ExitCode.INPUT,
            project_id=project_id,
        )
    return project


def _git_is_ancestor(repo_root: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", ancestor, descendant],
        check=False,
        capture_output=True,
    )
    return completed.returncode == 0


def _dependency_is_latest(project_dir: Path, reference: ObjectRef) -> bool:
    try:
        latest = find_object_ref(project_dir, reference.object_id)
    except FileNotFoundError:
        return False
    return latest.version == reference.version and latest.sha256 == reference.sha256


def _missing_research_contract(config: dict[str, Any]) -> list[str]:
    """Return machine-required G0 fields that still need a human decision."""

    missing: list[str] = []
    defaults = config.get("defaults")
    if not isinstance(defaults, dict):
        return ["defaults"]
    for key in ("paid_budget", "gpu_authorized", "experiment_concurrency"):
        if defaults.get(key) is None:
            missing.append(f"defaults.{key}")
    paid_budget = defaults.get("paid_budget")
    if (
        not isinstance(paid_budget, (int, float))
        or isinstance(paid_budget, bool)
        or paid_budget < 0
    ):
        missing.append("defaults.paid_budget")
    if not isinstance(defaults.get("gpu_authorized"), bool):
        missing.append("defaults.gpu_authorized")
    concurrency = defaults.get("experiment_concurrency")
    if not isinstance(concurrency, int) or isinstance(concurrency, bool) or concurrency < 1:
        missing.append("defaults.experiment_concurrency")

    contract = config.get("research_contract")
    if not isinstance(contract, dict):
        missing.append("research_contract")
    else:
        for key in ("success_criteria", "scope_in", "scope_out", "deliverables"):
            value = contract.get(key)
            if not isinstance(value, list) or not value:
                missing.append(f"research_contract.{key}")
        for key in ("confidentiality", "data_license_ethics", "public_query_boundary"):
            value = contract.get(key)
            if not isinstance(value, str) or not value.strip() or value == "unspecified":
                missing.append(f"research_contract.{key}")

    limits = config.get("limits")
    if not isinstance(limits, dict):
        missing.append("limits")
    else:
        for key in ("time_hours", "max_runs", "disk_mib"):
            value = limits.get(key)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
                missing.append(f"limits.{key}")
        data_scope = limits.get("data_scope")
        if not isinstance(data_scope, str) or not data_scope.strip():
            missing.append("limits.data_scope")
    return sorted(set(missing))


def _valid_gate_records(
    repo_root: Path, project_dir: Path
) -> tuple[set[GateKind], dict[GateKind, ObjectRef], dict[str, list[str]]]:
    store = LedgerStore(project_dir)
    manager = GateManager(store)
    current_head = git_head(repo_root)
    approved: set[GateKind] = set()
    refs: dict[GateKind, ObjectRef] = {}
    invalid: dict[str, list[str]] = {}
    for event in store.events():
        if event.event_type == "gate.invalidated":
            try:
                invalidated_gate = GateKind(str(event.payload["gate"]))
            except (KeyError, ValueError):
                continue
            approved.discard(invalidated_gate)
            refs.pop(invalidated_gate, None)
            invalid[invalidated_gate.value] = ["WORKFLOW_ROLLBACK"]
            continue
        if event.event_type != "gate.recorded" or event.object_ref is None:
            continue
        try:
            ledger_object = store.read_object(event.object_ref)
            record = GateRecord.model_validate(ledger_object.payload)
            valid, reasons = manager.validate(
                event.object_ref, current_basis_commit=record.basis_commit
            )
            if not _git_is_ancestor(repo_root, record.basis_commit, current_head):
                valid = False
                reasons = (*reasons, "BASIS_NOT_ANCESTOR")
            if any(
                not _dependency_is_latest(project_dir, ref) for ref in record.approved_dependencies
            ):
                valid = False
                reasons = (*reasons, "DEPENDENCY_SUPERSEDED")
        except (ValueError, OSError, GateError):
            valid, reasons = False, ("GATE_RECORD_INVALID",)
            record = None
        gate_name = record.gate.value if record is not None else str(event.payload.get("gate"))
        if record is not None:
            approved.discard(record.gate)
            refs.pop(record.gate, None)
        if valid and record is not None and record.decision is GateDecision.APPROVED:
            approved.add(record.gate)
            refs[record.gate] = event.object_ref
            invalid.pop(gate_name, None)
        else:
            invalid[gate_name] = list(reasons)
    return approved, refs, invalid


def _central_g2_approval(
    repo_root: Path, project_dir: Path
) -> tuple[dict[str, Any] | None, list[str]]:
    """Convert only a current ledger-validated G2 record into a delivery binding."""

    approved, refs, invalid = _valid_gate_records(repo_root, project_dir)
    if GateKind.G2 not in approved or GateKind.G2 not in refs:
        return None, invalid.get(GateKind.G2.value, ["G2_MISSING"])
    manifest_path = project_dir / "delivery" / "candidate" / "manifest.json"
    if not manifest_path.is_file():
        return None, ["CANDIDATE_MANIFEST_MISSING"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, ["CANDIDATE_MANIFEST_INVALID"]
    if not isinstance(manifest, dict):
        return None, ["CANDIDATE_MANIFEST_INVALID"]

    store = LedgerStore(project_dir)
    record_ref = refs[GateKind.G2]
    try:
        record = GateRecord.model_validate(store.read_object(record_ref).payload)
        packet = GateManager(store).read_packet(record.packet_ref)
        manifest_dependencies = [
            reference
            for reference in record.approved_dependencies
            if reference.object_type == "delivery.manifest"
        ]
        exact_bindings = [
            reference
            for reference in manifest_dependencies
            if store.read_object(reference).payload.get("document") == manifest
            and store.read_object(reference).payload.get("source_sha256")
            == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        ]
    except (OSError, ValueError):
        return None, ["G2_LEDGER_BINDING_INVALID"]
    if len(exact_bindings) != 1:
        return None, ["G2_MANIFEST_DEPENDENCY_MISMATCH"]
    manifest_level = manifest.get("reproducibility_level")
    if packet.reproduction_level is None or packet.reproduction_level.value != manifest_level:
        return None, ["G2_REPRODUCTION_LEVEL_MISMATCH"]
    return (
        {
            "gate_id": GateKind.G2.value,
            "status": GateDecision.APPROVED.value,
            "validation_source": "central_ledger",
            "gate_record_ref": record_ref.model_dump(mode="json"),
            "candidate_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "basis_commit": record.basis_commit,
            "accept_limited_reproduction": record.accept_limited_reproduction,
            "dependency_hashes": {},
        },
        [],
    )


@app.command("doctor")
def doctor() -> None:
    """检查本机科研工作流能力。"""

    repo_root = _repo()
    report = collect_doctor_report(repo_root)
    emit(envelope(ok=bool(report["ready"]), command="doctor", data=report))
    if not report["ready"]:
        raise typer.Exit(code=int(ExitCode.UNAVAILABLE))


@app.command("repo-scan")
def repo_scan(project_id: Annotated[str | None, typer.Option("--project-id")] = None) -> None:
    """扫描所有拟进入 Git 的项目文本，供人工检查和 pre-commit 使用。"""

    from .git_scan import scan_git_project_content

    repo_root = _repo()
    project_ids: tuple[str, ...]
    if project_id is not None:
        _project(repo_root, project_id)
        project_ids = (project_id,)
    else:
        projects_root = repo_root / "projects"
        project_ids = tuple(
            path.name for path in sorted(projects_root.iterdir()) if path.is_dir()
        )
    findings: list[dict[str, Any]] = []
    try:
        for current_id in project_ids:
            findings.extend(scan_git_project_content(repo_root, current_id))
    except (OSError, UnicodeError) as exc:
        fail(
            command="repo-scan",
            code="GIT_SCAN_UNAVAILABLE",
            message_zh=f"无法扫描拟进入 Git 的研究内容: {exc}",
            exit_code=ExitCode.UNAVAILABLE,
            project_id=project_id,
        )
    emit(
        envelope(
            ok=not findings,
            command="repo-scan",
            project_id=project_id,
            data={"scanned_projects": list(project_ids)},
            errors=findings,
        )
    )
    if findings:
        raise typer.Exit(code=int(ExitCode.INTEGRITY))


@project_app.command("init")
def project_init(
    project_id: str,
    title_zh: Annotated[str | None, typer.Option("--title-zh")] = None,
    title_en: Annotated[str | None, typer.Option("--title-en")] = None,
) -> None:
    """从受控模板创建新研究项目。"""

    repo_root = _repo()
    try:
        result = init_project(
            repo_root,
            project_id,
            title_zh or project_id,
            title_en or project_id,
        )
    except (ValueError, FileExistsError, FileNotFoundError) as exc:
        fail(
            command="project init",
            code="PROJECT_INIT_FAILED",
            message_zh=str(exc),
            exit_code=ExitCode.INPUT,
            project_id=project_id,
        )
    emit(envelope(ok=True, command="project init", project_id=project_id, data=result))


@app.command("status")
def status(project_id: str) -> None:
    repo_root = _repo()
    project_dir = _project(repo_root, project_id)
    try:
        store = LedgerStore(project_dir)
        audit = store.audit()
    except (ConcurrentWriteError, IntegrityError, OSError, ValueError) as exc:
        fail(
            command="status",
            code="LEDGER_INTEGRITY_UNAVAILABLE",
            message_zh=str(exc),
            exit_code=ExitCode.INTEGRITY,
            project_id=project_id,
        )
    try:
        state = store.require_valid_state()
    except ValueError as exc:
        fail(
            command="status",
            code="STATE_PROJECTION_INVALID",
            message_zh=f"状态投影缺失、过期或已损坏: {exc}",
            exit_code=ExitCode.INTEGRITY,
            project_id=project_id,
        )
    approved, _, invalid = _valid_gate_records(repo_root, project_dir)
    emit(
        envelope(
            ok=audit.ok,
            command="status",
            project_id=project_id,
            data={
                "state": state.model_dump(mode="json"),
                "integrity": audit.model_dump(mode="json"),
                "valid_gates": sorted(item.value for item in approved),
                "invalid_gates": invalid,
            },
        )
    )
    if not audit.ok:
        raise typer.Exit(code=int(ExitCode.INTEGRITY))


@app.command("validate")
def validate(project_id: str, strict: bool = typer.Option(False, "--strict")) -> None:
    from .paper import validate_paper

    repo_root = _repo()
    project_dir = _project(repo_root, project_id)
    try:
        store = LedgerStore(project_dir)
        audit = store.audit()
    except (ConcurrentWriteError, IntegrityError, OSError, ValueError) as exc:
        fail(
            command="validate",
            code="LEDGER_INTEGRITY_UNAVAILABLE",
            message_zh=str(exc),
            exit_code=ExitCode.INTEGRITY,
            project_id=project_id,
        )
    errors: list[dict[str, Any]] = [item.model_dump(mode="json") for item in audit.issues]
    warnings: list[dict[str, Any]] = []
    try:
        store.require_valid_state()
    except ValueError as exc:
        errors.append(
            {
                "code": "STATE_PROJECTION_INVALID",
                "message_zh": f"状态投影缺失、过期或已损坏: {exc}",
            }
        )
    approved, _, invalid = _valid_gate_records(repo_root, project_dir)
    for gate, reasons in invalid.items():
        warnings.append(
            {"code": "GATE_STALE", "message_zh": f"{gate} 已失效。", "details": reasons}
        )
    if strict:
        from .git_scan import scan_git_project_content

        try:
            errors.extend(scan_git_project_content(repo_root, project_id))
        except (OSError, UnicodeError) as exc:
            errors.append(
                {
                    "code": "GIT_SCAN_UNAVAILABLE",
                    "message_zh": f"无法扫描拟进入 Git 的研究内容: {exc}",
                }
            )
    paper_result: dict[str, Any] | None = None
    delivery_result: dict[str, Any] | None = None
    if (project_dir / "paper" / "citation-map.json").is_file():
        paper_result = validate_paper(repo_root, project_id)
        findings = paper_result.get("findings", [])
        target = errors if strict else warnings
        target.extend(findings)
    candidate_manifest = project_dir / "delivery" / "candidate" / "manifest.json"
    if candidate_manifest.is_file():
        from .delivery import assess_delivery_readiness

        delivery_result = assess_delivery_readiness(repo_root, project_id)
        if not delivery_result["ok"]:
            target = errors if strict else warnings
            target.extend(delivery_result["findings"])
    ok = not errors and (not strict or not warnings)
    emit(
        envelope(
            ok=ok,
            command="validate",
            project_id=project_id,
            data={
                "integrity": audit.model_dump(mode="json"),
                "paper": paper_result,
                "delivery": delivery_result,
                "valid_gates": sorted(item.value for item in approved),
            },
            errors=errors,
            warnings=warnings,
        )
    )
    if not ok:
        raise typer.Exit(code=int(ExitCode.INTEGRITY))


@ledger_app.command("record")
def ledger_record(
    project_id: str,
    object_type: str,
    source: Path,
    depends_on: Annotated[list[str] | None, typer.Option("--depends-on")] = None,
    supersedes: Annotated[str | None, typer.Option("--supersedes")] = None,
) -> None:
    """类型校验后，将候选 JSON/YAML 登记为不可变规范对象。"""

    repo_root = _repo()
    project_dir = _project(repo_root, project_id)
    source_path = source if source.is_absolute() else project_dir / source
    try:
        source_path = source_path.resolve()
        source_path.relative_to(project_dir)
        if not source_path.is_file():
            raise FileNotFoundError(f"候选对象不存在: {source}")
        dependencies = tuple(
            find_object_ref(project_dir, object_id) for object_id in (depends_on or [])
        )
        previous = find_object_ref(project_dir, supersedes) if supersedes else None
        reference = record_typed_payload(
            project_dir,
            project_id,
            source=source_path,
            object_type=object_type,
            dependencies=dependencies,
            supersedes=previous,
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        fail(
            command="ledger record",
            code="LEDGER_RECORD_REJECTED",
            message_zh=str(exc),
            exit_code=ExitCode.INPUT,
            project_id=project_id,
        )
    emit(
        envelope(
            ok=True,
            command="ledger record",
            project_id=project_id,
            data={"object_ref": reference.model_dump(mode="json")},
        )
    )


@app.command("transition")
def transition(
    project_id: str,
    target: ProjectStage,
    rollback: bool = typer.Option(False, "--rollback"),
) -> None:
    repo_root = _repo()
    project_dir = _project(repo_root, project_id)
    store = LedgerStore(project_dir)
    try:
        state = store.require_valid_state()
    except ValueError as exc:
        fail(
            command="transition",
            code="STATE_PROJECTION_INVALID",
            message_zh=f"状态投影缺失、过期或已损坏: {exc}",
            exit_code=ExitCode.INTEGRITY,
            project_id=project_id,
        )
    approved, gate_refs, _ = _valid_gate_records(repo_root, project_dir)
    gate_manager = GateManager(store)
    for kind, reference in gate_refs.items():
        gate_record = GateRecord.model_validate(store.read_object(reference).payload)
        gate_packet = gate_manager.read_packet(gate_record.packet_ref)
        state.gates[kind] = GateState(
            packet_id=gate_packet.packet_id,
            record_id=gate_record.record_id,
            approved=True,
            stale=False,
        )
    config = load_mapping(project_dir / "project.yaml")
    missing_contract = _missing_research_contract(config)
    if target is ProjectStage.EXPERIMENTING and missing_contract:
        fail(
            command="transition",
            code="EXPERIMENT_BOUNDARIES_MISSING",
            message_zh="实验前必须在 G0 研究合同中填写时间、运行次数、磁盘和数据边界。",
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
            details={"missing": missing_contract},
        )
    g1_required = bool(config.get("g1_required", False))
    if target is ProjectStage.EXPERIMENTING and g1_required and GateKind.G1 not in approved:
        fail(
            command="transition",
            code="G1_REQUIRED",
            message_zh="本项目触发了 G1，未批准前不能进入实验阶段。",
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
        )
    if target is ProjectStage.DELIVERY_READY:
        from .delivery import assess_delivery_readiness

        approval, approval_reasons = _central_g2_approval(repo_root, project_dir)
        readiness = assess_delivery_readiness(repo_root, project_id)
        if approval is None or not readiness["ok"]:
            fail(
                command="transition",
                code="G2_DELIVERY_BINDING_INVALID",
                message_zh="当前 G2 批准、候选包或证据闭包已失效，不能进入 delivery_ready。",
                exit_code=ExitCode.PRECONDITION,
                project_id=project_id,
                details={
                    "approval_reasons": approval_reasons,
                    "readiness_findings": readiness["findings"],
                },
            )
    if target is ProjectStage.DELIVERED:
        fail(
            command="transition",
            code="DELIVERED_REQUIRES_FINALIZE",
            message_zh="delivered 只能由 package finalize 在最终包和 annotated tag 均成功后写入。",
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
        )
    try:
        invalidated = state.transition(target, approved_gates=approved, rollback=rollback)
        dependencies = tuple(gate_refs[kind] for kind in sorted(gate_refs, key=str))
        for kind in invalidated:
            store.commit_object(
                project_id=project_id,
                object_type="gate.invalidation",
                payload={"gate": kind.value, "reason_zh": "上游阶段回退或依赖变化"},
                event_type="gate.invalidated",
                event_payload={"gate": kind.value},
            )
        transition_ref = store.commit_object(
            project_id=project_id,
            object_type="project.transition",
            payload={"target": target.value, "rollback": rollback},
            dependencies=dependencies,
            event_type="project.transitioned",
            event_payload={"target": target.value, "rollback": rollback},
        )
        store.write_state(state.model_dump(mode="json"))
    except (TransitionError, ConcurrentWriteError, ValueError) as exc:
        fail(
            command="transition",
            code="TRANSITION_REJECTED",
            message_zh=str(exc),
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
        )
    emit(
        envelope(
            ok=True,
            command="transition",
            project_id=project_id,
            data={
                "state": state.model_dump(mode="json"),
                "transition_ref": transition_ref.model_dump(mode="json"),
                "invalidated_gates": [item.value for item in invalidated],
            },
        )
    )


def _default_gate_artifact(project_dir: Path, gate: GateKind) -> tuple[Path, str]:
    if gate is GateKind.G0:
        return project_dir / "project.yaml", "project.charter"
    if gate is GateKind.G1:
        return project_dir / "experiments" / "protocol.md", "research.protocol"
    return project_dir / "delivery" / "candidate" / "manifest.json", "delivery.manifest"


def _gate_plan_path(project_dir: Path, plan_id: str) -> Path:
    candidates = (
        project_dir / "experiments" / "plans" / f"{plan_id}.json",
        project_dir / "plans" / f"{plan_id}.json",
        project_dir / "ledger" / "experiment_plans" / f"{plan_id}.json",
    )
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        raise GateError(f"G1 计划不存在: {plan_id}")
    return path.resolve()


@gate_app.command("request")
def gate_request(
    project_id: str,
    gate: GateKind,
    decision: Annotated[list[str], typer.Option("--decision", help="待人类确认的中文事项")],
    risk: Annotated[list[str] | None, typer.Option("--risk")] = None,
    budget: Annotated[list[str] | None, typer.Option("--budget")] = None,
    artifact: Annotated[Path | None, typer.Option("--artifact")] = None,
    plan_id: Annotated[str | None, typer.Option("--plan-id")] = None,
    reproduction_level: Annotated[str | None, typer.Option("--reproduction-level")] = None,
) -> None:
    from .models import ReproductionLevel

    repo_root = _repo()
    project_dir = _project(repo_root, project_id)
    if not git_is_clean(repo_root):
        fail(
            command="gate request",
            code="DIRTY_BASIS",
            message_zh="请求 Gate 前必须先提交待审制品，形成干净 basis_commit。",
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
        )
    default_path, object_type = _default_gate_artifact(project_dir, gate)
    source = artifact or default_path
    source = source if source.is_absolute() else project_dir / source
    plan_path: Path | None = None
    if gate is GateKind.G0 and source.resolve() != (project_dir / "project.yaml").resolve():
        fail(
            command="gate request",
            code="G0_ARTIFACT_MISMATCH",
            message_zh="G0 只能审阅并绑定当前项目的 project.yaml。",
            exit_code=ExitCode.INPUT,
            project_id=project_id,
        )
    if gate is GateKind.G1:
        try:
            if plan_id is None:
                raise GateError("G1 必须通过 --plan-id 指定待执行计划")
            plan_path = _gate_plan_path(project_dir, plan_id)
            plan_document = load_mapping(plan_path)
            protocol_binding = plan_document.get("protocol")
            if not isinstance(protocol_binding, dict) or not isinstance(
                protocol_binding.get("path"), str
            ):
                raise GateError("G1 计划缺少协议路径绑定")
            plan_protocol = (project_dir / protocol_binding["path"]).resolve()
            plan_protocol.relative_to(project_dir.resolve())
            if artifact is not None and source.resolve() != plan_protocol:
                raise GateError("G1 --artifact 必须是计划实际绑定的协议")
            source = plan_protocol
        except (OSError, ValueError, GateError) as exc:
            fail(
                command="gate request",
                code="G1_PLAN_BINDING_INVALID",
                message_zh=str(exc),
                exit_code=ExitCode.INPUT,
                project_id=project_id,
            )
    if not source.is_file():
        fail(
            command="gate request",
            code="GATE_ARTIFACT_MISSING",
            message_zh=f"待审制品不存在: {source}",
            exit_code=ExitCode.INPUT,
            project_id=project_id,
        )
    try:
        bundle_roots: tuple[ObjectRef, ...] = ()
        if gate is GateKind.G0:
            config = load_mapping(source)
            missing_contract = _missing_research_contract(config)
            if missing_contract:
                raise GateError("G0 研究合同字段尚未填写: " + ", ".join(missing_contract))
        effective_reproduction_level = (
            ReproductionLevel(reproduction_level) if reproduction_level else None
        )
        if gate is GateKind.G2:
            from .delivery import assess_delivery_readiness

            manifest = load_mapping(source)
            manifest_level = ReproductionLevel(str(manifest.get("reproducibility_level")))
            if (
                effective_reproduction_level is not None
                and effective_reproduction_level is not manifest_level
            ):
                raise GateError("G2 复现等级与候选 manifest 不一致")
            effective_reproduction_level = manifest_level
            readiness = assess_delivery_readiness(
                repo_root,
                project_id,
                manifest=manifest,
            )
            if not readiness["ok"]:
                codes = ", ".join(str(item.get("code")) for item in readiness["findings"])
                raise GateError("G2 证据、审核或披露条件未满足: " + codes)
            bundle_roots = tuple(
                ObjectRef.model_validate(raw_ref) for raw_ref in readiness["root_refs"]
            )
        if gate is GateKind.G1:
            assert plan_path is not None
            plan_ref = record_artifact(
                project_dir,
                project_id,
                source=plan_path,
                object_type="experiment.plan",
            )
            bundle_roots = (plan_ref,)
        root_ref = record_artifact(
            project_dir,
            project_id,
            source=source,
            object_type=object_type,
        )
        manager = GateManager(LedgerStore(project_dir))
        packet_ref = manager.request(
            project_id=project_id,
            gate=gate,
            basis_commit=git_head(repo_root),
            decisions_zh=decision,
            risks_zh=risk or (),
            budget_zh=budget or (),
            invalidation_conditions_zh=("任一批准依赖出现新版本、撤回或哈希变化",),
            dependency_roots=(root_ref, *bundle_roots),
            reproduction_level=effective_reproduction_level,
        )
    except (ValueError, GateError) as exc:
        fail(
            command="gate request",
            code="GATE_REQUEST_FAILED",
            message_zh=str(exc),
            exit_code=ExitCode.INPUT,
            project_id=project_id,
        )
    emit(
        envelope(
            ok=True,
            command="gate request",
            project_id=project_id,
            data={
                "gate": gate.value,
                "packet_ref": packet_ref.model_dump(mode="json"),
                "basis_commit": git_head(repo_root),
                "human_action_zh": "请审阅批准包；代理不得自行批准。",
            },
        )
    )


@gate_app.command("record")
def gate_record(
    project_id: str,
    packet_id: str,
    decision: GateDecision,
    approver: Annotated[str, typer.Option("--approver")],
    note_zh: Annotated[str, typer.Option("--note-zh")] = "",
    accept_limited: Annotated[bool, typer.Option("--accept-limited-reproduction")] = False,
    human_confirmation: Annotated[str, typer.Option("--human-confirmation")] = "",
) -> None:
    repo_root = _repo()
    project_dir = _project(repo_root, project_id)
    if decision is GateDecision.APPROVED and human_confirmation != "我已审阅并批准":
        fail(
            command="gate record",
            code="HUMAN_CONFIRMATION_REQUIRED",
            message_zh="批准必须由人类明确提供“我已审阅并批准”。",
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
        )
    try:
        packet_ref = find_object_ref(project_dir, packet_id)
        manager = GateManager(LedgerStore(project_dir))
        packet = manager.read_packet(packet_ref)
        current_head = git_head(repo_root)
        if not _git_is_ancestor(repo_root, packet.basis_commit, current_head):
            raise GateError("批准包 basis_commit 不在当前提交历史中")
        record_ref = manager.record(
            packet_ref=packet_ref,
            decision=decision,
            approver=approver,
            current_basis_commit=packet.basis_commit,
            accept_limited_reproduction=accept_limited,
            note_zh=note_zh,
        )
    except (FileNotFoundError, GateError, ValueError) as exc:
        fail(
            command="gate record",
            code="GATE_RECORD_FAILED",
            message_zh=str(exc),
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
        )
    emit(
        envelope(
            ok=True,
            command="gate record",
            project_id=project_id,
            data={"decision": decision.value, "record_ref": record_ref.model_dump(mode="json")},
        )
    )


@run_app.command("execute")
def run_execute(project_id: str, plan_id: str) -> None:
    from .runner import execute_run

    repo_root = _repo()
    project_dir = _project(repo_root, project_id)
    result = execute_run(repo_root, project_id, plan_id)
    run_id = result.get("run_id")
    if isinstance(run_id, str):
        plan_candidates = (
            project_dir / "experiments" / "plans" / f"{plan_id}.json",
            project_dir / "plans" / f"{plan_id}.json",
            project_dir / "ledger" / "experiment_plans" / f"{plan_id}.json",
        )
        plan_path = next((path for path in plan_candidates if path.is_file()), None)
        run_path = project_dir / "runs" / run_id / "run.json"
        try:
            if plan_path is None or not run_path.is_file():
                raise FileNotFoundError("运行计划或 run.json 不存在")
            if result.get("status") in {"completed", "partial", "failed"} and result.get(
                "authorization"
            ):
                run_ref = record_experiment_run(project_dir, project_id, plan_path, result)
            else:
                run_ref = record_artifact(
                    project_dir,
                    project_id,
                    source=run_path,
                    object_type="experiment.attempt",
                )
            result["ledger_ref"] = run_ref.model_dump(mode="json")
        except (FileNotFoundError, OSError, ValueError) as exc:
            fail(
                command="run execute",
                code="RUN_LEDGER_RECORD_FAILED",
                message_zh=f"运行已结束，但规范台账登记失败: {exc}",
                exit_code=ExitCode.INTEGRITY,
                project_id=project_id,
            )
    ok = result.get("status") == "completed"
    run_errors = []
    if not ok:
        run_errors.append(
            {
                "code": str(result.get("error_code") or result.get("failure_kind") or "RUN_FAILED"),
                "message_zh": str(result.get("message") or "实验运行未完成。"),
            }
        )
    emit(
        envelope(
            ok=ok,
            command="run execute",
            project_id=project_id,
            data=result,
            errors=run_errors,
        )
    )
    if not ok:
        raise typer.Exit(code=int(_run_failure_exit_code(result)))


@paper_app.command("build")
def paper_build(project_id: str) -> None:
    from .paper import build_paper

    repo_root = _repo()
    _project(repo_root, project_id)
    result = build_paper(repo_root, project_id)
    ok = result.get("status") == "built"
    emit(envelope(ok=ok, command="paper build", project_id=project_id, data=result))
    if not ok:
        code = (
            ExitCode.UNAVAILABLE
            if result.get("status") == "tool_unavailable"
            else ExitCode.INTEGRITY
        )
        raise typer.Exit(code=int(code))


@package_app.command("prepare")
def package_prepare(
    project_id: str,
    reproducibility_level: Annotated[str, typer.Option("--reproduction-level")] = "full",
) -> None:
    from .delivery import prepare_package

    repo_root = _repo()
    _project(repo_root, project_id)
    result = prepare_package(repo_root, project_id, reproducibility_level=reproducibility_level)
    ok = result.get("status") == "prepared"
    emit(envelope(ok=ok, command="package prepare", project_id=project_id, data=result))
    if not ok:
        raise typer.Exit(code=int(ExitCode.INTEGRITY))


@package_app.command("finalize")
def package_finalize(project_id: str) -> None:
    from .delivery import finalize_package, valid_package_id

    repo_root = _repo()
    project_dir = _project(repo_root, project_id)
    store = LedgerStore(project_dir)
    try:
        state = store.require_valid_state()
    except ValueError as exc:
        fail(
            command="package finalize",
            code="STATE_PROJECTION_INVALID",
            message_zh=f"状态投影缺失、过期或已损坏: {exc}",
            exit_code=ExitCode.INTEGRITY,
            project_id=project_id,
        )
    if state.stage is not ProjectStage.DELIVERY_READY:
        fail(
            command="package finalize",
            code="DELIVERY_READY_REQUIRED",
            message_zh="只有 delivery_ready 阶段可以执行最终交付。",
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
        )
    if not git_is_clean(repo_root):
        fail(
            command="package finalize",
            code="DIRTY_COMPLETION_COMMIT",
            message_zh="最终交付前必须提交 G2 记录和状态，形成干净的完成提交。",
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
        )
    approval, reasons = _central_g2_approval(repo_root, project_dir)
    if approval is None:
        fail(
            command="package finalize",
            code="G2_LEDGER_BINDING_INVALID",
            message_zh="没有找到与当前候选 manifest 精确绑定的有效中央 G2 批准。",
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
            details={"reasons": reasons},
        )
    manifest_path = project_dir / "delivery" / "candidate" / "manifest.json"
    try:
        manifest = load_mapping(manifest_path)
        package_id = str(manifest["package_id"])
    except (KeyError, OSError, ValueError) as exc:
        fail(
            command="package finalize",
            code="CANDIDATE_MANIFEST_INVALID",
            message_zh=f"候选 manifest 无效: {exc}",
            exit_code=ExitCode.INTEGRITY,
            project_id=project_id,
        )
    if not valid_package_id(package_id):
        fail(
            command="package finalize",
            code="PACKAGE_ID_INVALID",
            message_zh="候选包 package_id 无效或可能导致路径越界",
            exit_code=ExitCode.INPUT,
            project_id=project_id,
        )
    tag_name = f"aiscience-{project_id}-{package_id}"
    tag_exists = _completion_git(
        repo_root, "show-ref", "--verify", "--quiet", f"refs/tags/{tag_name}"
    )
    if tag_exists.returncode == 0:
        fail(
            command="package finalize",
            code="COMPLETION_TAG_EXISTS",
            message_zh=f"完成 tag 已存在，拒绝覆盖: {tag_name}",
            exit_code=ExitCode.PRECONDITION,
            project_id=project_id,
        )
    if tag_exists.returncode not in {0, 1}:
        fail(
            command="package finalize",
            code="COMPLETION_TAG_CHECK_FAILED",
            message_zh=f"无法检查完成 tag: {tag_exists.stderr.strip()}",
            exit_code=ExitCode.UNAVAILABLE,
            project_id=project_id,
        )
    try:
        original_head = git_head(repo_root)
        branch_ref = _completed_stdout(
            _completion_git(repo_root, "symbolic-ref", "-q", "HEAD"),
            "resolve completion branch",
        )
        if not branch_ref.startswith("refs/heads/"):
            raise RuntimeError("completion branch is not a local branch")
        initial_index_tree = _completed_stdout(
            _completion_git(repo_root, "write-tree"), "snapshot completion index"
        )
        committer_ident = _completed_stdout(
            _completion_git(repo_root, "var", "GIT_COMMITTER_IDENT"),
            "resolve Git committer identity",
        )
    except RuntimeError as exc:
        fail(
            command="package finalize",
            code="COMPLETION_GIT_PREFLIGHT_FAILED",
            message_zh=f"完成提交预检失败: {exc}",
            exit_code=ExitCode.UNAVAILABLE,
            project_id=project_id,
        )
    result = finalize_package(
        repo_root,
        project_id,
        approval=approval,
        create_tag=False,
    )
    ok = result.get("status") == "awaiting_completion_tag"
    if ok:
        events_before = store.events_path.read_bytes() if store.events_path.is_file() else None
        state_before = store.state_path.read_bytes() if store.state_path.is_file() else None
        created_object_paths: list[Path] = []
        final_path = (project_dir / str(result["final_path"])).resolve()
        final_root = (project_dir / "delivery" / "final").resolve()
        try:
            final_path.relative_to(final_root)
        except ValueError:
            result = {**result, "status": "failed", "reason": "final_path_escape"}
            ok = False
        refs_updated = False
        try:
            if not ok:
                raise RuntimeError("final package path escaped delivery/final")
            gate_ref = ObjectRef.model_validate(approval["gate_record_ref"])
            finalization_ref = store.commit_object(
                project_id=project_id,
                object_type="delivery.finalization",
                payload={
                    "package_id": package_id,
                    "manifest_sha256": result["manifest_sha256"],
                    "final_path": result["final_path"],
                    "annotated_tag": tag_name,
                },
                dependencies=(gate_ref,),
                require_current=(gate_ref,),
                event_type="delivery.finalized",
                event_payload={"package_id": package_id, "annotated_tag": tag_name},
            )
            created_object_paths.append(project_dir / finalization_ref.path)
            state.transition(ProjectStage.DELIVERED, approved_gates=(GateKind.G2,))
            transition_ref = store.commit_object(
                project_id=project_id,
                object_type="project.transition",
                payload={"target": ProjectStage.DELIVERED.value, "rollback": False},
                dependencies=(gate_ref, finalization_ref),
                event_type="project.transitioned",
                event_payload={"target": ProjectStage.DELIVERED.value, "rollback": False},
            )
            created_object_paths.append(project_dir / transition_ref.path)
            store.write_state(state.model_dump(mode="json"))
            tracked_paths = (
                project_dir / finalization_ref.path,
                project_dir / transition_ref.path,
                store.events_path,
                store.state_path,
            )
            relative_paths = [
                path.resolve().relative_to(repo_root.resolve()).as_posix()
                for path in tracked_paths
            ]
            staged = _completion_git(
                repo_root,
                "add",
                "--",
                *relative_paths,
            )
            if staged.returncode != 0:
                raise RuntimeError(f"git add failed: {staged.stderr.strip()}")
            completion_tree = _completed_stdout(
                _completion_git(repo_root, "write-tree"), "write completion tree"
            )
            completion_commit = _completed_stdout(
                _completion_git(
                    repo_root,
                    "commit-tree",
                    completion_tree,
                    "-p",
                    original_head,
                    input_text=f"deliver: finalize {project_id} {package_id}\n",
                ),
                "create completion commit",
            )
            tag_message = (
                f"Finalize {project_id} {package_id}\n"
                f"candidate_manifest_sha256={result['manifest_sha256']}"
            )
            tag_object = _completed_stdout(
                _completion_git(
                    repo_root,
                    "mktag",
                    input_text=(
                        f"object {completion_commit}\n"
                        "type commit\n"
                        f"tag {tag_name}\n"
                        f"tagger {committer_ident}\n\n"
                        f"{tag_message}\n"
                    ),
                ),
                "create annotated tag object",
            )
            ref_transaction = _completion_git(
                repo_root,
                "update-ref",
                "--stdin",
                input_text=(
                    "start\n"
                    f"create refs/tags/{tag_name} {tag_object}\n"
                    f"update {branch_ref} {completion_commit} {original_head}\n"
                    "prepare\n"
                    "commit\n"
                ),
            )
            if ref_transaction.returncode != 0:
                raise RuntimeError(
                    "atomic completion ref update failed: "
                    f"{ref_transaction.stderr.strip() or ref_transaction.stdout.strip()}"
                )
            refs_updated = True
            result.update(
                {
                    "status": "finalized",
                    "completion_commit": completion_commit,
                    "finalization_ref": finalization_ref.model_dump(mode="json"),
                    "transition_ref": transition_ref.model_dump(mode="json"),
                    "tag": {"created": True, "name": tag_name},
                }
            )
        except (ConcurrentWriteError, OSError, RuntimeError, ValueError) as exc:
            rollback_errors: list[str] = []
            if not refs_updated:
                restored_index = _completion_git(repo_root, "read-tree", initial_index_tree)
                if restored_index.returncode != 0:
                    rollback_errors.append(f"index: {restored_index.stderr.strip()}")
                try:
                    if events_before is None:
                        store.events_path.unlink(missing_ok=True)
                    else:
                        atomic_write(store.events_path, events_before)
                    if state_before is None:
                        store.state_path.unlink(missing_ok=True)
                    else:
                        atomic_write(store.state_path, state_before)
                    for object_path in created_object_paths:
                        object_path.unlink(missing_ok=True)
                    if final_path.is_dir():
                        shutil.rmtree(final_path)
                except OSError as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
            result = {
                **result,
                "status": "failed",
                "reason": "completion_commit_or_tag_failed",
                "message": str(exc),
                "rolled_back": not refs_updated and not rollback_errors,
                "rollback_errors": rollback_errors,
            }
    ok = result.get("status") == "finalized"
    emit(envelope(ok=ok, command="package finalize", project_id=project_id, data=result))
    if not ok:
        exit_code = (
            ExitCode.INTEGRITY
            if result.get("status") == "failed"
            else ExitCode.PRECONDITION
        )
        raise typer.Exit(code=int(exit_code))


@app.command("demo")
def demo(
    project_id: str = typer.Option("demo-robust-location", "--project-id"),
    overwrite: bool = typer.Option(False, "--overwrite"),
) -> None:
    from .demo import create_demo

    repo_root = _repo()
    try:
        result = create_demo(repo_root, project_id=project_id, overwrite=overwrite)
    except (OSError, ValueError) as exc:
        fail(
            command="demo",
            code="DEMO_INPUT_REJECTED",
            message_zh=str(exc),
            exit_code=ExitCode.INPUT,
            project_id=project_id,
        )
    ok = result.get("status") in {"created", "prepared"}
    emit(envelope(ok=ok, command="demo", project_id=project_id, data=result))
    if not ok:
        raise typer.Exit(code=int(ExitCode.INTEGRITY))


if __name__ == "__main__":
    app()
