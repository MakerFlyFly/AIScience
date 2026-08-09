"""Convert runner output into canonical, typed experiment ledger records."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .integrity import IntegrityError
from .local_cas import validate_local_cas_manifest
from .models import (
    ID_PATTERN,
    ExperimentRecord,
    ObjectRef,
    ReproductionLevel,
    ResourceControl,
    RunStatus,
)
from .scaffold import record_artifact
from .storage import LedgerStore

_RUN_STATUS = {
    "completed": RunStatus.SUCCEEDED,
    "partial": RunStatus.PARTIAL,
    "failed": RunStatus.FAILED,
}


def _current_protocol_ref(store: LedgerStore, result: dict[str, Any]) -> ObjectRef:
    authorization = result.get("authorization")
    protocol = authorization.get("protocol") if isinstance(authorization, dict) else None
    if not isinstance(protocol, dict):
        raise ValueError("运行记录缺少已授权协议绑定")
    path = protocol.get("path")
    digest = protocol.get("sha256")
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
        recorded_path = payload.get("source_path", payload.get("path"))
        recorded_digest = payload.get("sha256", payload.get("source_sha256"))
        if recorded_path == path and recorded_digest == digest and payload.get("frozen") is True:
            return reference
    raise ValueError("运行授权所用协议未找到当前冻结台账对象")


def _metadata_ref(
    store: LedgerStore,
    *,
    project_id: str,
    object_type: str,
    payload: dict[str, Any],
) -> ObjectRef:
    return store.commit_object(
        project_id=project_id,
        object_type=object_type,
        payload=payload,
        event_type=f"{object_type}.recorded",
    )


def _current_source_binding_ref(
    store: LedgerStore,
    *,
    object_type: str,
    source_path: str,
    source_sha256: str,
) -> ObjectRef | None:
    for event in reversed(store.events()):
        reference = event.object_ref
        if reference is None or reference.object_type != object_type:
            continue
        try:
            if not store.is_current_reference(reference):
                continue
            payload = store.read_object(reference).payload
            if (
                payload.get("source_path") == source_path
                and payload.get("source_sha256", payload.get("sha256")) == source_sha256
                and not store.source_binding_issues(reference)
            ):
                return reference
        except IntegrityError:
            continue
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _retry_predecessor(
    store: LedgerStore, project_id: str, run_id: str, value: object
) -> ObjectRef | None:
    if value is None:
        return None
    if not isinstance(value, str) or value == run_id:
        raise ValueError("retry_of 必须引用另一条同项目运行")
    predecessor_ref: ObjectRef | None = None
    for event in reversed(store.events()):
        reference = event.object_ref
        if (
            reference is not None
            and reference.object_type == "experiment"
            and reference.object_id == value
        ):
            predecessor_ref = reference
            break
    if predecessor_ref is None:
        raise ValueError("retry_of 引用的前序运行不存在于当前项目")
    if not store.is_current_reference(predecessor_ref):
        raise ValueError("retry_of 引用的前序运行不是当前版本")
    predecessor = ExperimentRecord.model_validate(store.read_object(predecessor_ref).payload)
    if predecessor.project_id != project_id:
        raise ValueError("retry_of 不得跨项目引用")
    if predecessor.status not in {RunStatus.FAILED, RunStatus.PARTIAL}:
        raise ValueError("只能重试 failed 或 partial 前序运行")
    return predecessor_ref


def _source_metadata_ref(
    store: LedgerStore,
    *,
    project_dir: Path,
    project_id: str,
    object_type: str,
    source: Path,
    metadata: dict[str, Any],
) -> ObjectRef:
    source = source.resolve()
    relative = source.relative_to(project_dir.resolve()).as_posix()
    if not source.is_file():
        raise FileNotFoundError(f"运行追踪制品不存在: {relative}")
    return _metadata_ref(
        store,
        project_id=project_id,
        object_type=object_type,
        payload={
            "source_path": relative,
            "source_sha256": _sha256(source),
            "metadata": metadata,
        },
    )


def _path_bindings(
    store: LedgerStore,
    *,
    project_id: str,
    object_type: str,
    values: object,
) -> tuple[ObjectRef, ...]:
    if not isinstance(values, list):
        return ()
    references: list[ObjectRef] = []
    for value in values:
        if not isinstance(value, dict):
            continue
        path = value.get("path")
        digest = value.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            continue
        existing = _current_source_binding_ref(
            store,
            object_type=object_type,
            source_path=path,
            source_sha256=digest,
        )
        if existing is not None:
            references.append(existing)
            continue
        references.append(
            _metadata_ref(
                store,
                project_id=project_id,
                object_type=object_type,
                payload={"source_path": path, "source_sha256": digest},
            )
        )
    return tuple(references)


def record_experiment_run(
    project_dir: Path,
    project_id: str,
    plan_path: Path,
    result: dict[str, Any],
) -> ObjectRef:
    """Anchor one authorized runner result as an ``ExperimentRecord``."""

    run_id = result.get("run_id")
    if not isinstance(run_id, str) or ID_PATTERN.fullmatch(run_id) is None:
        raise ValueError("运行结果缺少安全的 run_id")
    status = _RUN_STATUS.get(str(result.get("status")))
    if status is None:
        raise ValueError("只有完成授权的运行才能登记为规范实验")
    run_root = project_dir / "runs" / run_id
    run_json = run_root / "run.json"
    if not run_json.is_file():
        raise ValueError("运行目录缺少 run.json")
    try:
        archived_run = json.loads(run_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("run.json 无法读取") from exc
    if not isinstance(archived_run, dict) or any(
        archived_run.get(key) != result.get(key)
        for key in ("run_id", "status", "basis_commit", "argv")
    ):
        raise ValueError("run.json 身份字段与 runner 返回结果不一致")
    store = LedgerStore(project_dir)
    retry_ref = _retry_predecessor(store, project_id, run_id, result.get("retry_of"))
    plan_relative = plan_path.resolve().relative_to(project_dir.resolve()).as_posix()
    plan_digest = _sha256(plan_path)
    plan_ref = _current_source_binding_ref(
        store,
        object_type="experiment.plan",
        source_path=plan_relative,
        source_sha256=plan_digest,
    )
    if plan_ref is None:
        plan_ref = record_artifact(
            project_dir,
            project_id,
            source=plan_path,
            object_type="experiment.plan",
        )
    protocol_ref = _current_protocol_ref(store, result)
    authorization = result.get("authorization")
    assert isinstance(authorization, dict)
    data_refs = _path_bindings(
        store,
        project_id=project_id,
        object_type="experiment.input",
        values=authorization.get("inputs"),
    )
    script_refs = _path_bindings(
        store,
        project_id=project_id,
        object_type="experiment.script",
        values=authorization.get("scripts"),
    )
    logs = result.get("logs")
    log_refs: list[ObjectRef] = []
    local_only_trace = False
    trace_incomplete = False
    if isinstance(logs, dict):
        for stream_name, value in sorted(logs.items()):
            if isinstance(value, dict):
                log_path = value.get("path")
                if not isinstance(log_path, str):
                    raise ValueError(f"{stream_name} 日志缺少路径")
                source = run_root / log_path
                if value.get("storage_policy") == "local_cas":
                    validate_local_cas_manifest(project_dir, source)
                    local_only_trace = True
                log_refs.append(
                    _source_metadata_ref(
                        store,
                        project_dir=project_dir,
                        project_id=project_id,
                        object_type="experiment.log",
                        source=source,
                        metadata={"stream": stream_name, **value},
                    )
                )
    if not isinstance(logs, dict) or set(logs) != {"stdout", "stderr"}:
        trace_incomplete = True
    output_refs: list[ObjectRef] = [
        _source_metadata_ref(
            store,
            project_dir=project_dir,
            project_id=project_id,
            object_type="experiment.run_record",
            source=run_json,
            metadata={"run_id": run_id},
        )
    ]
    outputs = result.get("outputs")
    if isinstance(outputs, list):
        for value in outputs:
            if isinstance(value, dict):
                if value.get("storage_policy") == "local_cas":
                    relative_source = value.get("cas_manifest_path")
                else:
                    relative_source = value.get("archived_path")
                if not isinstance(relative_source, str):
                    raise ValueError("运行输出缺少可追踪归档或 CAS manifest")
                source = run_root / relative_source
                if value.get("storage_policy") == "local_cas":
                    validate_local_cas_manifest(project_dir, source)
                    local_only_trace = True
                output_refs.append(
                    _source_metadata_ref(
                        store,
                        project_dir=project_dir,
                        project_id=project_id,
                        object_type="experiment.artifact",
                        source=source,
                        metadata=value,
                    )
                )
    enforcement = result.get("enforcement")
    resource_controls = {
        name: ResourceControl(value)
        for name, value in (enforcement.items() if isinstance(enforcement, dict) else ())
        if isinstance(value, str) and value in {item.value for item in ResourceControl}
    }
    environment = result.get("environment")
    environment_sha256 = (
        environment.get("fingerprint_sha256") if isinstance(environment, dict) else None
    )
    if not isinstance(environment_sha256, str):
        raise ValueError("运行记录缺少环境指纹")
    seed_values = result.get("seeds")
    if isinstance(seed_values, dict):
        seeds = tuple(value for _, value in sorted(seed_values.items()) if isinstance(value, int))
    elif isinstance(seed_values, list):
        seeds = tuple(value for value in seed_values if isinstance(value, int))
    else:
        seeds = ()
    command = result.get("argv")
    if not isinstance(command, list) or not command or not all(
        isinstance(value, str) for value in command
    ):
        raise ValueError("运行记录缺少参数数组")
    reproduction = ReproductionLevel(str(result.get("reproducibility", "partial")))
    if local_only_trace and reproduction is ReproductionLevel.FULL:
        reproduction = ReproductionLevel.LOCAL_ONLY
    elif trace_incomplete and reproduction is ReproductionLevel.FULL:
        reproduction = ReproductionLevel.PARTIAL
    deviations = tuple(
        str(value)
        for value in (result.get("missing_outputs") or [])
        if isinstance(value, str)
    )
    if result.get("failure_kind"):
        deviations = (*deviations, f"failure_kind={result['failure_kind']}")
    hardware = result.get("hardware")
    if not isinstance(hardware, dict):
        hardware = {}
    record = ExperimentRecord(
        run_id=run_id,
        project_id=project_id,
        plan_ref=plan_ref,
        protocol_ref=protocol_ref,
        data_refs=data_refs,
        environment_sha256=environment_sha256,
        basis_commit=str(result.get("basis_commit")),
        command=tuple(command),
        seeds=seeds,
        hardware=hardware,
        status=status,
        log_refs=tuple(log_refs),
        artifact_refs=(*script_refs, *output_refs),
        deviations_zh=deviations,
        retry_of=retry_ref,
        resource_controls=resource_controls,
        reproduction_level=reproduction,
    )
    dependencies = (
        plan_ref,
        protocol_ref,
        *data_refs,
        *script_refs,
        *log_refs,
        *output_refs,
        *((retry_ref,) if retry_ref is not None else ()),
    )
    reference = store.commit_object(
        project_id=project_id,
        object_type="experiment",
        object_id=run_id,
        payload=record.model_dump(mode="json"),
        dependencies=dependencies,
        event_type=(
            "experiment.completed" if status is RunStatus.SUCCEEDED else "experiment.recorded"
        ),
    )
    return reference


__all__ = ["record_experiment_run"]
