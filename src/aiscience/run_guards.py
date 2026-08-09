"""Fail-closed authorization checks for formal experiment execution.

The plan is bound to the *actual* clean Git HEAD that contains it.  It therefore
never embeds its own commit hash; protocol, script, and input content are bound by
explicit SHA-256 values instead.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .gates import GateManager
from .integrity import IntegrityError
from .models import GateKind, GateRecord, ObjectRef, ProjectStage, ProjectStatus
from .state import StateProjectionError
from .storage import LedgerStore


class RunGuardError(ValueError):
    """Stable precondition failure suitable for a CLI/API error envelope."""

    def __init__(self, code: str, message_zh: str, **details: Any) -> None:
        super().__init__(message_zh)
        self.code = code
        self.message_zh = message_zh
        self.details = details


class InputUnavailable(RunGuardError):
    def __init__(self, missing: list[str]) -> None:
        super().__init__("INPUT_UNAVAILABLE", "实验输入不可用。", missing=missing)
        self.missing = missing


@dataclass(frozen=True)
class RunAuthorization:
    basis_commit: str
    mode: str
    protocol: dict[str, str]
    scripts: tuple[dict[str, str], ...]
    inputs: tuple[dict[str, str], ...]
    budget: dict[str, Any]
    requirements: dict[str, Any]
    valid_gates: tuple[str, ...]
    g1_triggers: tuple[str, ...]

    def as_record(self) -> dict[str, Any]:
        return {
            "basis_commit": self.basis_commit,
            "mode": self.mode,
            "protocol": self.protocol,
            "scripts": list(self.scripts),
            "inputs": list(self.inputs),
            "budget": self.budget,
            "requirements": self.requirements,
            "valid_gates": list(self.valid_gates),
            "g1_triggers": list(self.g1_triggers),
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(repo_root: Path, *args: str, binary: bool = False) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=not binary,
        encoding=None if binary else "utf-8",
        errors=None if binary else "replace",
    )


def require_clean_head(repo_root: Path, plan_path: Path) -> str:
    """Return the current clean HEAD and prove that it contains the exact plan bytes."""

    head = _git(repo_root, "rev-parse", "HEAD")
    if head.returncode != 0:
        raise RunGuardError("GIT_HEAD_MISSING", "仓库没有可用的 HEAD 提交。")
    status = _git(repo_root, "status", "--porcelain=v1", "--untracked-files=all")
    if status.returncode != 0:
        raise RunGuardError("GIT_STATUS_UNAVAILABLE", "无法检查 Git 工作区状态。")
    if str(status.stdout).strip():
        raise RunGuardError("GIT_WORKTREE_DIRTY", "实验要求干净工作区。")
    try:
        relative = plan_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:
        raise RunGuardError("PLAN_PATH_OUTSIDE_REPOSITORY", "实验计划越出仓库边界。") from exc
    tracked = _git(repo_root, "ls-files", "--error-unmatch", "--", relative)
    if tracked.returncode != 0:
        raise RunGuardError("PLAN_NOT_COMMITTED", "实验计划必须由当前 HEAD 跟踪。")
    committed = _git(repo_root, "show", f"HEAD:{relative}", binary=True)
    if committed.returncode != 0:
        raise RunGuardError("PLAN_NOT_AT_HEAD", "当前计划内容与 HEAD 中的版本不一致。")
    if committed.stdout != plan_path.read_bytes():
        raise RunGuardError(
            "GIT_NORMALIZATION_MISMATCH",
            "计划的工作树原始字节与 HEAD blob 不一致；请先按仓库属性规范化换行后再提交。",
            path=relative,
        )
    return str(head.stdout).strip()


def _require_head_blob_bytes(repo_root: Path, head: str, path: Path) -> None:
    """Reject clean-filter-only equality so raw SHA bindings survive a fresh clone."""

    try:
        relative = path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:
        raise RunGuardError(
            "BOUND_FILE_OUTSIDE_REPOSITORY", "实验依赖文件越出 Git 仓库。"
        ) from exc
    committed = _git(repo_root, "show", f"{head}:{relative}", binary=True)
    if committed.returncode != 0:
        raise RunGuardError(
            "BOUND_FILE_NOT_AT_HEAD", "实验依赖文件未由当前 HEAD 跟踪。", path=relative
        )
    if committed.stdout != path.read_bytes():
        raise RunGuardError(
            "GIT_NORMALIZATION_MISMATCH",
            "实验依赖的工作树原始字节与 HEAD blob 不一致；请规范化换行后再提交。",
            path=relative,
        )


def _inside(project_root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise RunGuardError("PLAN_PATH_INVALID", "计划中的路径必须是非空项目相对路径。")
    path = Path(value)
    if path.is_absolute():
        raise RunGuardError("PLAN_PATH_ABSOLUTE", "计划不得包含绝对路径。", path=value)
    candidate = (project_root / path).resolve()
    try:
        candidate.relative_to(project_root.resolve())
    except ValueError as exc:
        raise RunGuardError("PLAN_PATH_ESCAPE", "计划路径越出项目边界。", path=value) from exc
    return candidate


def _bound_file(project_root: Path, item: object, kind: str) -> dict[str, str]:
    if not isinstance(item, dict):
        raise RunGuardError("PLAN_BINDING_MISSING", f"{kind} 必须包含 path 和 sha256。")
    path_value = item.get("path")
    expected = item.get("sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise RunGuardError("PLAN_HASH_MISSING", f"{kind} 缺少固定 SHA-256。", path=path_value)
    path = _inside(project_root, path_value)
    if not path.is_file():
        raise InputUnavailable([str(path_value)])
    actual = _sha256(path)
    if actual != expected:
        raise RunGuardError(
            "BOUND_FILE_CHANGED", f"{kind} 的 SHA-256 与计划不一致。", path=path_value
        )
    return {"path": str(path_value).replace("\\", "/"), "sha256": actual}


def _load_project_config(project_root: Path) -> dict[str, Any]:
    path = project_root / "project.yaml"
    if not path.is_file():
        raise RunGuardError("PROJECT_CONTRACT_MISSING", "缺少 project.yaml 研究合同。")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RunGuardError("PROJECT_CONTRACT_INVALID", "project.yaml 无法读取。") from exc
    if not isinstance(value, dict):
        raise RunGuardError("PROJECT_CONTRACT_INVALID", "project.yaml 必须是对象。")
    return value


def _mapping(parent: dict[str, Any], key: str, code: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise RunGuardError(code, f"项目或计划缺少 {key} 对象。")
    return value


def _positive_number(parent: dict[str, Any], key: str, code: str) -> float:
    value = parent.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise RunGuardError(code, f"{key} 必须是大于 0 的数值。")
    return float(value)


def _nonnegative_number(parent: dict[str, Any], key: str, code: str) -> float:
    value = parent.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise RunGuardError(code, f"{key} 必须是非负数值。")
    return float(value)


def _git_is_ancestor(repo_root: Path, ancestor: str, head: str) -> bool:
    result = _git(repo_root, "merge-base", "--is-ancestor", ancestor, head)
    return result.returncode == 0


def _valid_gate_records(
    repo_root: Path, store: LedgerStore, head: str
) -> dict[GateKind, ObjectRef]:
    manager = GateManager(store)
    records: dict[GateKind, ObjectRef] = {}
    for event in store.events():
        if event.event_type == "gate.invalidated":
            try:
                records.pop(GateKind(str(event.payload["gate"])), None)
            except (KeyError, ValueError):
                records.clear()
            continue
        reference = event.object_ref
        if event.event_type != "gate.recorded" or reference is None:
            continue
        try:
            ledger_object = store.read_object(reference)
            record = GateRecord.model_validate(ledger_object.payload)
            valid, _ = manager.validate(reference, current_basis_commit=record.basis_commit)
        except (IntegrityError, ValueError):
            continue
        if valid and _git_is_ancestor(repo_root, record.basis_commit, head):
            records[record.gate] = reference
    return records


def _gate_basis_contains_current_file(
    repo_root: Path, store: LedgerStore, reference: ObjectRef, path: Path
) -> bool:
    """Whether a gate basis contains the current Git-normalized file content."""

    try:
        record = GateRecord.model_validate(store.read_object(reference).payload)
        relative = path.resolve().relative_to(repo_root.resolve()).as_posix()
    except (IntegrityError, ValueError):
        return False
    compared = _git(repo_root, "diff", "--quiet", record.basis_commit, "--", relative)
    if compared.returncode != 0:
        return False
    committed = _git(repo_root, "show", f"{record.basis_commit}:{relative}", binary=True)
    return committed.returncode == 0 and committed.stdout == path.read_bytes()


def _gate_approves_current_file(
    store: LedgerStore,
    reference: ObjectRef,
    project_root: Path,
    path: Path,
) -> bool:
    """Require the exact current source binding to appear in the human-approved closure."""

    try:
        record = GateRecord.model_validate(store.read_object(reference).payload)
        relative = path.resolve().relative_to(project_root.resolve()).as_posix()
        digest = _sha256(path)
        for dependency in record.approved_dependencies:
            if not store.is_current_reference(dependency):
                continue
            payload = store.read_object(dependency).payload
            source_path = payload.get("source_path", payload.get("path"))
            source_sha256 = payload.get("source_sha256", payload.get("sha256"))
            if source_path == relative and source_sha256 == digest:
                return not store.source_binding_issues(dependency)
    except (IntegrityError, OSError, ValueError):
        return False
    return False


def _require_formal_state(store: LedgerStore) -> None:
    report = store.audit()
    if not report.ok:
        raise RunGuardError("LEDGER_INTEGRITY_FAILED", "项目台账完整性校验失败。")
    try:
        state = store.require_valid_state()
    except (IntegrityError, StateProjectionError, ValueError) as exc:
        raise RunGuardError("PROJECT_STATE_INVALID", "项目状态投影缺失、过期或已损坏。") from exc
    if state.status is not ProjectStatus.ACTIVE:
        raise RunGuardError("PROJECT_STATUS_BLOCKS_RUN", "项目当前状态禁止启动实验。")
    if state.stage is not ProjectStage.EXPERIMENTING:
        raise RunGuardError("PROJECT_STAGE_BLOCKS_RUN", "仅 experimenting 阶段允许执行实验。")


def _require_frozen_protocol(store: LedgerStore, binding: dict[str, str]) -> None:
    for event in reversed(store.events()):
        reference = event.object_ref
        if reference is None or reference.object_type != "research.protocol":
            continue
        try:
            if not store.is_current_reference(reference):
                continue
            payload = store.read_object(reference).payload
        except IntegrityError:
            continue
        source_path = payload.get("source_path", payload.get("path"))
        source_hash = payload.get("sha256", payload.get("source_sha256"))
        if (
            payload.get("frozen") is True
            and source_path == binding["path"]
            and source_hash == binding["sha256"]
        ):
            return
    raise RunGuardError(
        "PROTOCOL_NOT_FROZEN", "计划引用的协议没有当前、冻结且哈希一致的台账记录。"
    )


def _project_usage(project_root: Path) -> tuple[int, float, float]:
    count = 0
    duration_hours = 0.0
    paid_cost = 0.0
    for path in (project_root / "runs").glob("*/run.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RunGuardError("RUN_HISTORY_INVALID", "既有运行记录无法读取。") from exc
        count += 1
        duration = record.get("duration_seconds", 0)
        if isinstance(duration, (int, float)) and not isinstance(duration, bool):
            duration_hours += max(0.0, float(duration)) / 3600
        guard = record.get("authorization", {})
        budget = guard.get("budget", {}) if isinstance(guard, dict) else {}
        paid = budget.get("estimated_paid_cost", 0) if isinstance(budget, dict) else 0
        if isinstance(paid, (int, float)) and not isinstance(paid, bool):
            paid_cost += max(0.0, float(paid))
    return count, duration_hours, paid_cost


def _project_size_mib(project_root: Path) -> float:
    total = 0
    for path in project_root.rglob("*"):
        if path.is_file():
            total += path.stat().st_size
    return total / (1024 * 1024)


def _require_contract(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = _mapping(config, "research_contract", "PROJECT_CONTRACT_MISSING")
    required_lists = ("success_criteria", "scope_in", "deliverables")
    for key in required_lists:
        value = contract.get(key)
        if not isinstance(value, list) or not value:
            raise RunGuardError("PROJECT_CONTRACT_INCOMPLETE", f"研究合同缺少非空 {key}。")
    for key in ("confidentiality", "data_license_ethics", "public_query_boundary"):
        value = contract.get(key)
        if not isinstance(value, str) or not value.strip() or value == "unspecified":
            raise RunGuardError("PROJECT_CONTRACT_INCOMPLETE", f"研究合同缺少明确 {key}。")
    limits = _mapping(config, "limits", "PROJECT_LIMITS_MISSING")
    _positive_number(limits, "time_hours", "PROJECT_LIMIT_MISSING")
    max_runs = _positive_number(limits, "max_runs", "PROJECT_LIMIT_MISSING")
    if not max_runs.is_integer():
        raise RunGuardError("PROJECT_LIMIT_INVALID", "max_runs 必须是正整数。")
    _positive_number(limits, "disk_mib", "PROJECT_LIMIT_MISSING")
    data_scope = limits.get("data_scope")
    if not isinstance(data_scope, (str, list)) or not data_scope:
        raise RunGuardError("PROJECT_LIMIT_MISSING", "data_scope 必须明确填写。")
    defaults = _mapping(config, "defaults", "PROJECT_DEFAULTS_MISSING")
    _nonnegative_number(defaults, "paid_budget", "PROJECT_DEFAULT_MISSING")
    for key in ("gpu_authorized", "network_after_g0"):
        if not isinstance(defaults.get(key), bool):
            raise RunGuardError("PROJECT_DEFAULT_MISSING", f"{key} 必须明确为布尔值。")
    concurrency = defaults.get("experiment_concurrency")
    if concurrency != 1:
        raise RunGuardError("PROJECT_CONCURRENCY_UNSUPPORTED", "v1 仅支持实验并发为 1。")
    return limits, defaults


def _require_budget_and_risk(
    project_root: Path,
    plan: dict[str, Any],
    config: dict[str, Any],
    limits: dict[str, Any],
    defaults: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], tuple[str, ...]]:
    budget = _mapping(plan, "budget", "PLAN_BUDGET_MISSING")
    requested_time = _positive_number(budget, "estimated_time_hours", "PLAN_BUDGET_INCOMPLETE")
    estimated_runs = _positive_number(budget, "estimated_runs", "PLAN_BUDGET_INCOMPLETE")
    if estimated_runs != 1:
        raise RunGuardError(
            "PLAN_RUN_COUNT_INVALID", "单次 execute 计划的 estimated_runs 必须为 1。"
        )
    requested_disk = _nonnegative_number(budget, "estimated_disk_mib", "PLAN_BUDGET_INCOMPLETE")
    requested_paid = _nonnegative_number(
        budget, "estimated_paid_cost", "PLAN_BUDGET_INCOMPLETE"
    )
    data_scope = budget.get("data_scope")
    if not isinstance(data_scope, (str, list)) or not data_scope:
        raise RunGuardError("PLAN_BUDGET_INCOMPLETE", "计划必须声明 data_scope。")

    timeout = plan.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise RunGuardError("PLAN_TIMEOUT_INVALID", "timeout_seconds 必须明确为正数。")
    if float(timeout) / 3600 > requested_time:
        raise RunGuardError("PLAN_TIME_ESTIMATE_TOO_SMALL", "超时上限超过计划时间预算。")

    triggers: list[str] = []
    count, duration, paid = _project_usage(project_root)
    if count + 1 > int(limits["max_runs"]):
        triggers.append("budget_exception:max_runs")
    if duration + requested_time > float(limits["time_hours"]):
        triggers.append("budget_exception:time_hours")
    if _project_size_mib(project_root) + requested_disk > float(limits["disk_mib"]):
        triggers.append("budget_exception:disk_mib")
    if paid + requested_paid > float(defaults["paid_budget"]):
        triggers.append("budget_exception:paid_cost")
    allowed_scope = limits["data_scope"]
    requested_scope = {data_scope} if isinstance(data_scope, str) else set(data_scope)
    allowed = {allowed_scope} if isinstance(allowed_scope, str) else set(allowed_scope)
    if not requested_scope or not requested_scope <= allowed:
        raise RunGuardError("DATA_SCOPE_EXCEEDED", "计划数据范围超出 G0 研究合同。")

    requirements = _mapping(plan, "requirements", "PLAN_REQUIREMENTS_MISSING")
    for key in (
        "network",
        "gpu",
        "sensitive_data",
        "external_action",
        "irreversible",
        "high_risk",
    ):
        if not isinstance(requirements.get(key), bool):
            raise RunGuardError("PLAN_REQUIREMENTS_INCOMPLETE", f"requirements.{key} 必须明确。")
    isolation = requirements.get("isolation")
    if not isinstance(isolation, dict):
        raise RunGuardError("PLAN_REQUIREMENTS_INCOMPLETE", "必须声明 isolation 要求。")
    capability = {
        "process_tree": "best_effort",
        "network": "observed_only",
        "filesystem": "observed_only",
        "gpu": "observed_only",
        "memory": "observed_only",
    }
    strength = {"observed_only": 0, "best_effort": 1, "hard": 2}
    for key, available in capability.items():
        required = isolation.get(key)
        if required not in strength:
            raise RunGuardError("PLAN_ISOLATION_INCOMPLETE", f"isolation.{key} 必须明确。")
        if strength[str(required)] > strength[available]:
            triggers.append(f"isolation_gap:{key}")
    if requirements["gpu"] and not defaults["gpu_authorized"]:
        triggers.append("g0_exception:gpu")
    if requirements["network"] and not defaults["network_after_g0"]:
        triggers.append("g0_exception:network")
    if requirements["network"]:
        triggers.append("network")
    if requirements["gpu"]:
        triggers.append("gpu")
    if requested_paid > 0:
        triggers.append("paid_service")
    for key in ("sensitive_data", "external_action", "irreversible", "high_risk"):
        if requirements[key]:
            triggers.append(key)
    if config.get("g1_required") is True:
        triggers.append("project_g1_required")
    return dict(budget), dict(requirements), tuple(sorted(set(triggers)))


def _require_output_declarations(
    project_root: Path, plan: dict[str, Any], requirements: dict[str, Any]
) -> None:
    outputs = plan.get("expected_outputs")
    if not isinstance(outputs, list) or not outputs:
        raise RunGuardError("PLAN_OUTPUTS_MISSING", "正式计划必须声明至少一个预期输出。")
    any_sensitive = False
    seen: set[str] = set()
    for item in outputs:
        if not isinstance(item, dict):
            raise RunGuardError(
                "PLAN_OUTPUT_CLASSIFICATION_MISSING",
                "正式计划的每个输出都必须声明 path、sensitive 和 redistributable。",
            )
        path = item.get("path")
        sensitive = item.get("sensitive")
        redistributable = item.get("redistributable")
        if not isinstance(sensitive, bool) or not isinstance(redistributable, bool):
            raise RunGuardError(
                "PLAN_OUTPUT_CLASSIFICATION_MISSING", "输出敏感性与再分发许可必须明确。"
            )
        normalized = str(path).replace("\\", "/") if isinstance(path, str) else ""
        _inside(project_root, normalized)
        if normalized in seen:
            raise RunGuardError("PLAN_OUTPUT_DUPLICATE", "预期输出路径重复。", path=normalized)
        seen.add(normalized)
        any_sensitive = any_sensitive or sensitive
    if any_sensitive != bool(requirements["sensitive_data"]):
        raise RunGuardError(
            "SENSITIVE_DECLARATION_MISMATCH",
            "requirements.sensitive_data 与输出敏感性声明不一致。",
        )


def _is_demo_fixture(project_root: Path, project_id: str, plan: dict[str, Any]) -> bool:
    if (
        plan.get("execution_mode") != "demo_fixture"
        or plan.get("demo_only") is not True
        or not project_id.startswith("demo-")
    ):
        return False
    marker = project_root / "gates" / "DEMO-G2.json"
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(value, dict) and value.get("status") == "demo_only_not_human_approval"


def authorize_run(
    repo_root: Path,
    project_root: Path,
    project_id: str,
    plan_path: Path,
    plan: dict[str, Any],
) -> RunAuthorization:
    """Authorize a plan or raise a stable, fail-closed error."""

    if "basis_commit" in plan:
        raise RunGuardError(
            "PLAN_BASIS_SELF_REFERENCE_FORBIDDEN",
            "计划不得嵌入 basis_commit；执行时绑定包含该计划的干净当前 HEAD。",
        )
    head = require_clean_head(repo_root, plan_path)
    protocol = _bound_file(project_root, plan.get("protocol"), "protocol")
    raw_scripts = plan.get("scripts")
    if not isinstance(raw_scripts, list) or not raw_scripts:
        raise RunGuardError("PLAN_SCRIPTS_MISSING", "计划必须声明至少一个脚本及其 SHA-256。")
    scripts = tuple(_bound_file(project_root, item, "script") for item in raw_scripts)
    argv = plan.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        raise RunGuardError("PLAN_ARGV_INVALID", "argv 必须是非空字符串数组。")
    normalized_argv = {item.replace("\\", "/") for item in argv}
    if not any(item["path"] in normalized_argv for item in scripts):
        raise RunGuardError("SCRIPT_NOT_IN_ARGV", "固定哈希的脚本必须出现在 argv 中。")
    raw_inputs = plan.get("inputs")
    if not isinstance(raw_inputs, list):
        raise RunGuardError("PLAN_INPUTS_INVALID", "inputs 必须是数组。")
    inputs: list[dict[str, str]] = []
    missing: list[str] = []
    for item in raw_inputs:
        try:
            inputs.append(_bound_file(project_root, item, "input"))
        except InputUnavailable as exc:
            missing.extend(exc.missing)
    if missing:
        raise InputUnavailable(missing)

    for binding in (protocol, *scripts, *inputs):
        _require_head_blob_bytes(repo_root, head, project_root / binding["path"])

    if _is_demo_fixture(project_root, project_id, plan):
        return RunAuthorization(
            basis_commit=head,
            mode="demo_fixture",
            protocol=protocol,
            scripts=scripts,
            inputs=tuple(inputs),
            budget={},
            requirements={},
            valid_gates=(),
            g1_triggers=(),
        )
    if plan.get("execution_mode", "formal") != "formal" or plan.get("demo_only") is True:
        raise RunGuardError("EXECUTION_MODE_INVALID", "未识别或未隔离的执行模式。")

    store = LedgerStore(project_root)
    _require_formal_state(store)
    _require_frozen_protocol(store, protocol)
    config = _load_project_config(project_root)
    limits, defaults = _require_contract(config)
    budget, requirements, triggers = _require_budget_and_risk(
        project_root, plan, config, limits, defaults
    )
    _require_output_declarations(project_root, plan, requirements)
    records = _valid_gate_records(repo_root, store, head)
    g0 = records.get(GateKind.G0)
    if g0 is not None:
        project_file = project_root / "project.yaml"
        if not _gate_basis_contains_current_file(
            repo_root, store, g0, project_file
        ) or not _gate_approves_current_file(store, g0, project_root, project_file):
            records.pop(GateKind.G0, None)
    g1 = records.get(GateKind.G1)
    if g1 is not None and (
        not _gate_basis_contains_current_file(repo_root, store, g1, plan_path)
        or not _gate_approves_current_file(store, g1, project_root, plan_path)
        or not _gate_approves_current_file(
            store, g1, project_root, project_root / protocol["path"]
        )
    ):
        records.pop(GateKind.G1, None)
    if GateKind.G0 not in records:
        raise RunGuardError("G0_REQUIRED", "缺少对当前依赖仍有效的 G0 人类批准。")
    if triggers and GateKind.G1 not in records:
        raise RunGuardError(
            "G1_REQUIRED", "该计划触发条件执行 Gate，但没有有效 G1 批准。", triggers=triggers
        )
    return RunAuthorization(
        basis_commit=head,
        mode="formal",
        protocol=protocol,
        scripts=scripts,
        inputs=tuple(inputs),
        budget=budget,
        requirements=requirements,
        valid_gates=tuple(sorted(kind.value for kind in records)),
        g1_triggers=triggers,
    )


__all__ = [
    "InputUnavailable",
    "RunAuthorization",
    "RunGuardError",
    "authorize_run",
    "require_clean_head",
]
