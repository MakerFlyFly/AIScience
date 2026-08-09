"""Traceable experiment execution with conservative resource-control claims."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout

from .local_cas import archive_output
from .models import new_id
from .run_guards import InputUnavailable, RunAuthorization, RunGuardError, authorize_run
from .security import redact_text

_SAFE_ENVIRONMENT_KEYS = {
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "PATH",
    "PATHEXT",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TZ",
    "WINDIR",
}
_SENSITIVE_ENVIRONMENT_WORDS = (
    "AUTH",
    "COOKIE",
    "CREDENTIAL",
    "KEY",
    "PASSWORD",
    "SECRET",
    "TOKEN",
)

def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inside(root: Path, value: str | Path) -> Path:
    root = root.resolve()
    candidate = (root / value).resolve() if not Path(value).is_absolute() else Path(value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"路径越出项目边界: {value}") from exc
    return candidate


def _plan_path(project_root: Path, plan_id: str) -> Path | None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", plan_id):
        return None
    candidates = (
        project_root / "experiments" / "plans" / f"{plan_id}.json",
        project_root / "plans" / f"{plan_id}.json",
        project_root / "ledger" / "experiment_plans" / f"{plan_id}.json",
    )
    for path in candidates:
        resolved = path.resolve()
        try:
            resolved.relative_to(project_root.resolve())
        except ValueError:
            continue
        if resolved.is_file():
            return resolved
    return None


def _hardware() -> dict[str, Any]:
    result: dict[str, Any] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
    }
    try:
        import psutil  # type: ignore[import-untyped]

        result["memory_bytes"] = psutil.virtual_memory().total
        result["cpu_model"] = platform.processor() or None
    except (ImportError, OSError):
        result["memory_bytes"] = None
    result["gpu"] = {"value": None, "evidence": "unknown"}
    return result


class _WindowsJob:
    """Best-effort Windows Job Object wrapper.

    Assignment happens immediately after creation, but not atomically with process creation; the
    enforcement label therefore remains ``best_effort`` even when the job is active.
    """

    def __init__(self) -> None:
        self.handle: int | None = None
        self.assigned = False

    @staticmethod
    def _kernel32() -> Any:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        kernel32.SetInformationJobObject.restype = ctypes.c_int
        kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        kernel32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel32.TerminateJobObject.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        return kernel32

    def assign(self, process: subprocess.Popen[bytes]) -> bool:
        if os.name != "nt":
            return False
        try:
            kernel32 = self._kernel32()

            class _BasicLimit(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", ctypes.c_uint32),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", ctypes.c_uint32),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", ctypes.c_uint32),
                    ("SchedulingClass", ctypes.c_uint32),
                ]

            class _IoCounters(ctypes.Structure):
                _fields_ = [(name, ctypes.c_uint64) for name in (
                    "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                    "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
                )]

            class _ExtendedLimit(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", _BasicLimit),
                    ("IoInfo", _IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return False
            limits = _ExtendedLimit()
            limits.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
            configured = kernel32.SetInformationJobObject(
                handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
            )
            process_handle = ctypes.c_void_p(int(process._handle))  # type: ignore[attr-defined]
            assigned = configured and kernel32.AssignProcessToJobObject(handle, process_handle)
            if not assigned:
                kernel32.CloseHandle(handle)
                return False
            self.handle = int(handle)
            self.assigned = True
            return True
        except (AttributeError, OSError, TypeError, ValueError):
            return False

    def terminate(self) -> None:
        if self.handle is None:
            return
        try:
            kernel32 = self._kernel32()
            kernel32.TerminateJobObject(self.handle, 124)
        except OSError:
            pass

    def close(self) -> None:
        if self.handle is None:
            return
        with suppress(OSError):
            self._kernel32().CloseHandle(self.handle)
        self.handle = None


def _kill_process_tree(process: subprocess.Popen[bytes], job: _WindowsJob) -> None:
    if job.assigned:
        job.terminate()
    elif os.name == "nt":
        try:
            import psutil

            parent = psutil.Process(process.pid)
            descendants = parent.children(recursive=True)
            for child in descendants:
                child.terminate()
            parent.terminate()
            _, alive = psutil.wait_procs([*descendants, parent], timeout=2)
            for item in alive:
                item.kill()
        except (ImportError, OSError):
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)  # type: ignore[attr-defined]
        except (ProcessLookupError, PermissionError):
            process.kill()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def _recorded_argv(argv: list[str], project_root: Path) -> tuple[list[str], tuple[str, ...]]:
    recorded: list[str] = []
    redaction_kinds: set[str] = set()
    for index, value in enumerate(argv):
        candidate = Path(value)
        if not candidate.is_absolute():
            redacted, kinds = redact_text(value)
            recorded.append(redacted)
            redaction_kinds.update(kinds)
            continue
        try:
            recorded.append(candidate.resolve().relative_to(project_root).as_posix())
        except ValueError:
            label = "$EXECUTABLE" if index == 0 else "$ABSOLUTE_PATH"
            redacted, kinds = redact_text(f"{label}/{candidate.name}")
            recorded.append(redacted)
            redaction_kinds.update(kinds)
    return recorded, tuple(sorted(redaction_kinds))


def _sanitized_log(path: Path) -> tuple[str, ...]:
    text = path.read_bytes().decode("utf-8", errors="replace")
    redacted, kinds = redact_text(text)
    if redacted != text:
        path.write_text(redacted, encoding="utf-8", newline="\n")
    return kinds


def _archive_sanitized_log(
    project_root: Path,
    run_root: Path,
    raw_path: Path,
    stream_name: str,
) -> dict[str, Any]:
    redactions = _sanitized_log(raw_path)
    archived = archive_output(
        project_root=project_root,
        run_root=run_root,
        output_path=raw_path,
        relative_path=f"logs/{stream_name}.log",
        declared_sensitive=False,
        redistributable=True,
    )
    if archived["storage_policy"] == "local_cas":
        path = archived.get("cas_manifest_path")
    else:
        path = archived.get("archived_path")
        raw_path.unlink(missing_ok=True)
    if not isinstance(path, str):
        raise ValueError("日志归档没有可追踪路径")
    return {
        "path": path,
        "sha256": archived.get("sha256"),
        "size_bytes": archived.get("size_bytes"),
        "storage_policy": archived.get("storage_policy"),
        "cas_address": archived.get("cas_address"),
        "redactions": list(redactions),
    }


def _record_unavailable(
    project_root: Path, plan_id: str, plan_path: Path | None, missing: list[str]
) -> dict[str, Any]:
    run_id = new_id("run")
    run_root = project_root / "runs" / run_id
    record: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": run_id,
        "plan_id": plan_id,
        "status": "input_unavailable",
        "failure_kind": None,
        "missing_inputs": missing,
        "plan_path": plan_path.relative_to(project_root).as_posix() if plan_path else None,
        "created_at": _utc_now(),
        "reproducibility": "unavailable",
    }
    _write_json(run_root / "run.json", record)
    return record


def _finish_run(
    *,
    repo_root: Path,
    project_root: Path,
    plan_id: str,
    plan: dict[str, Any],
    plan_path: Path,
    plan_sha256: str,
    authorization: RunAuthorization,
    argv: list[str],
    cwd: Path,
    timeout: int | float,
    run_id: str,
    run_root: Path,
    stdout_path: Path,
    stderr_path: Path,
    started: float,
    start_time: str,
    timed_out: bool,
    return_code: int | None,
    launch_error: str | None,
    assigned: bool,
    input_records: list[dict[str, Any]],
    overrides: dict[str, str],
    environment: dict[str, str],
) -> dict[str, Any]:
    expected_outputs = plan.get("expected_outputs", [])
    if not isinstance(expected_outputs, list):
        expected_outputs = []
        launch_error = launch_error or "expected_outputs 无效"
    outputs: list[dict[str, Any]] = []
    missing_outputs: list[str] = []
    for declaration in expected_outputs:
        if isinstance(declaration, str):
            value = declaration
            declared_sensitive = False
            redistributable = True
        elif (
            isinstance(declaration, dict)
            and isinstance(declaration.get("path"), str)
            and isinstance(declaration.get("sensitive", False), bool)
            and isinstance(declaration.get("redistributable", True), bool)
        ):
            value = declaration["path"]
            declared_sensitive = bool(declaration.get("sensitive", False))
            redistributable = bool(declaration.get("redistributable", True))
        else:
            launch_error = launch_error or "expected_outputs 声明无效"
            continue
        try:
            output_path = _inside(project_root, value)
        except ValueError:
            missing_outputs.append(value)
            continue
        if not output_path.is_file():
            missing_outputs.append(value)
            continue
        try:
            outputs.append(
                archive_output(
                    project_root=project_root,
                    run_root=run_root,
                    output_path=output_path,
                    relative_path=output_path.relative_to(project_root).as_posix(),
                    declared_sensitive=declared_sensitive,
                    redistributable=redistributable,
                )
            )
        except (OSError, ValueError) as exc:
            launch_error = launch_error or f"artifact_archive:{type(exc).__name__}"

    logs: dict[str, dict[str, Any]] = {}
    try:
        logs["stdout"] = _archive_sanitized_log(
            project_root, run_root, stdout_path, "stdout"
        )
        logs["stderr"] = _archive_sanitized_log(
            project_root, run_root, stderr_path, "stderr"
        )
    except (OSError, ValueError) as exc:
        launch_error = launch_error or f"log_archive:{type(exc).__name__}"
    status = "completed"
    failure_kind: str | None = None
    if timed_out:
        status, failure_kind = "failed", "timeout"
    elif launch_error is not None:
        status, failure_kind = "failed", "launch"
    elif return_code != 0:
        status, failure_kind = "failed", "process_exit"
    elif missing_outputs:
        status, failure_kind = "partial", "missing_output"
    try:
        final_plan_sha256 = _sha256(plan_path)
    except OSError:
        final_plan_sha256 = None
    if final_plan_sha256 != plan_sha256:
        status, failure_kind = "failed", "plan_changed_during_run"
    uv_lock_path = repo_root / "uv.lock"
    uv_lock_hash = _sha256(uv_lock_path) if uv_lock_path.is_file() else None
    inherited_names = sorted(name for name in os.environ if name in environment)
    environment_fingerprint = {
        "python": sys.version,
        "platform": platform.platform(),
        "override_names": sorted(overrides),
        "inherited_names": inherited_names,
        "uv_lock_sha256": uv_lock_hash,
        "environment_values_sha256": hashlib.sha256(
            json.dumps(environment, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    recorded_argv, argv_redactions = _recorded_argv(argv, project_root)
    record = {
        "schema_version": "1.0",
        "run_id": run_id,
        "plan_id": plan_id,
        "retry_of": plan.get("retry_of"),
        "plan_sha256": plan_sha256,
        "plan_final_sha256": final_plan_sha256,
        "basis_commit": authorization.basis_commit,
        "authorization": authorization.as_record(),
        "status": status,
        "failure_kind": failure_kind,
        "message": launch_error,
        "argv": recorded_argv,
        "argv_redactions": list(argv_redactions),
        "shell": False,
        "cwd": cwd.relative_to(project_root).as_posix() or ".",
        "timeout_seconds": float(timeout),
        "timed_out": timed_out,
        "return_code": return_code,
        "started_at": start_time,
        "finished_at": _utc_now(),
        "duration_seconds": round(time.monotonic() - started, 6),
        "inputs": input_records,
        "outputs": outputs,
        "missing_outputs": missing_outputs,
        "seeds": plan.get("seeds", {}),
        "hardware": _hardware(),
        "environment": {
            "override_names": sorted(overrides),
            "inherited_names": inherited_names,
            "executable": Path(shutil.which(argv[0]) or argv[0]).name,
            "fingerprint_sha256": hashlib.sha256(
                json.dumps(environment_fingerprint, sort_keys=True).encode("utf-8")
            ).hexdigest(),
            "values_sha256": environment_fingerprint["environment_values_sha256"],
            "uv_lock_sha256": uv_lock_hash,
            "evidence": "observed",
        },
        "logs": logs,
        "enforcement": {
            "shell_disabled": "hard",
            "working_directory": "observed_only",
            "timeout_main_process": "hard",
            "process_tree": "best_effort",
            "windows_job_object_assigned": bool(assigned) if os.name == "nt" else None,
            "network": "observed_only",
            "cpu": "observed_only",
            "memory": "observed_only",
            "gpu": "observed_only",
            "filesystem_boundary": "observed_only",
        },
        "reproducibility": (
            "local_only"
            if status == "completed"
            and (
                any(output.get("storage_policy") == "local_cas" for output in outputs)
                or any(log.get("storage_policy") == "local_cas" for log in logs.values())
            )
            else "full"
            if status == "completed"
            else "partial"
        ),
    }
    _write_json(run_root / "run.json", record)
    return record


def execute_run(repo_root: Path, project_id: str, plan_id: str) -> dict[str, Any]:
    """Execute one JSON experiment plan without a shell and return its run record.

    Concurrency is intentionally controlled by the caller. This function only writes to its own
    newly generated ``run_id`` directory.
    """

    repo_root = Path(repo_root).resolve()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", plan_id):
        return {
            "status": "failed",
            "failure_kind": "invalid_plan_id",
            "message": "plan_id 只能包含安全的小写字母、数字、下划线和连字符",
        }
    project_root = _inside(repo_root / "projects", project_id)
    if not project_root.is_dir():
        return {"status": "input_unavailable", "missing_inputs": ["project"]}
    plan_path = _plan_path(project_root, plan_id)
    if plan_path is None:
        return _record_unavailable(project_root, plan_id, None, [f"plan:{plan_id}"])
    try:
        plan_bytes = plan_path.read_bytes()
        plan_sha256 = hashlib.sha256(plan_bytes).hexdigest()
        plan = json.loads(plan_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "failed", "failure_kind": "invalid_plan", "message": str(exc)}

    if not isinstance(plan, dict):
        return {"status": "failed", "failure_kind": "invalid_plan", "message": "计划必须是对象"}
    retry_of = plan.get("retry_of")
    if retry_of is not None and (
        not isinstance(retry_of, str)
        or not re.fullmatch(r"run_[A-Za-z0-9][A-Za-z0-9_-]{6,95}", retry_of)
    ):
        return {
            "status": "failed",
            "failure_kind": "invalid_plan",
            "message": "retry_of 必须是同项目中的安全 run_id",
        }
    argv = plan.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(v, str) for v in argv):
        return {
            "status": "failed",
            "failure_kind": "invalid_plan",
            "message": "argv 必须是非空字符串数组；不接受 shell 命令字符串",
        }
    try:
        authorization = authorize_run(repo_root, project_root, project_id, plan_path, plan)
    except InputUnavailable as exc:
        return _record_unavailable(project_root, plan_id, plan_path, exc.missing)
    except RunGuardError as exc:
        return {
            "status": "failed",
            "failure_kind": "precondition",
            "error_code": exc.code,
            "message": exc.message_zh,
            **exc.details,
        }

    try:
        cwd = _inside(project_root, str(plan.get("cwd", ".")))
    except ValueError as exc:
        return {"status": "failed", "failure_kind": "invalid_plan", "message": str(exc)}
    if not cwd.is_dir():
        return _record_unavailable(
            project_root, plan_id, plan_path, [f"cwd:{plan.get('cwd', '.')}"]
        )

    input_records: list[dict[str, Any]] = [
        *authorization.inputs,
        authorization.protocol,
        *authorization.scripts,
    ]

    timeout = plan.get("timeout_seconds", 300)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        return {
            "status": "failed",
            "failure_kind": "invalid_plan",
            "message": "timeout_seconds 无效",
        }

    inherited = plan.get("inherit_environment", [])
    if not isinstance(inherited, list) or not all(isinstance(value, str) for value in inherited):
        return {
            "status": "failed",
            "failure_kind": "invalid_plan",
            "message": "inherit_environment 必须是环境变量名数组",
        }
    inherited_names = _SAFE_ENVIRONMENT_KEYS | {value.upper() for value in inherited}
    sensitive_inheritance = sorted(
        name
        for name in inherited_names
        if any(word in name for word in _SENSITIVE_ENVIRONMENT_WORDS)
    )
    if sensitive_inheritance:
        return {
            "status": "failed",
            "failure_kind": "unsafe_environment",
            "message": "拒绝继承疑似敏感环境变量",
            "environment_names": sensitive_inheritance,
        }
    environment = {
        name: value for name, value in os.environ.items() if name.upper() in inherited_names
    }
    overrides = plan.get("environment", {})
    if not isinstance(overrides, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in overrides.items()
    ):
        return {"status": "failed", "failure_kind": "invalid_plan", "message": "environment 无效"}
    unsafe_override_names = sorted(
        name
        for name in overrides
        if any(word in name.upper() for word in _SENSITIVE_ENVIRONMENT_WORDS)
    )
    if unsafe_override_names:
        return {
            "status": "failed",
            "failure_kind": "unsafe_environment",
            "message": "计划不能内嵌疑似密钥环境变量",
            "environment_names": unsafe_override_names,
        }
    environment.update(overrides)

    lock_root = project_root / ".aiscience-data"
    lock_root.mkdir(parents=True, exist_ok=True)
    execution_lock = FileLock(lock_root / "run.lock", timeout=0)
    try:
        execution_lock.acquire()
    except Timeout:
        return {
            "status": "failed",
            "failure_kind": "concurrent_run",
            "message": "项目已有实验正在运行",
        }

    try:
        # Close the authorization-to-launch window after obtaining the per-project
        # execution lock.  This catches a concurrent commit or input mutation before
        # any tracked run output is created.
        try:
            locked_authorization = authorize_run(
                repo_root, project_root, project_id, plan_path, plan
            )
        except InputUnavailable as exc:
            return _record_unavailable(project_root, plan_id, plan_path, exc.missing)
        except RunGuardError as exc:
            return {
                "status": "failed",
                "failure_kind": "precondition",
                "error_code": exc.code,
                "message": exc.message_zh,
                **exc.details,
            }
        if locked_authorization.basis_commit != authorization.basis_commit:
            return {
                "status": "failed",
                "failure_kind": "precondition",
                "error_code": "BASIS_CHANGED_BEFORE_LAUNCH",
                "message": "授权后、启动前 Git basis 发生变化。",
            }
        authorization = locked_authorization
        run_id = new_id("run")
        run_root = project_root / "runs" / run_id
        run_root.mkdir(parents=True, exist_ok=False)
        staging_root = project_root / ".aiscience-data" / "run-staging" / run_id
        staging_root.mkdir(parents=True, exist_ok=False)
        stdout_path = staging_root / "stdout.raw"
        stderr_path = staging_root / "stderr.raw"
        creationflags = 0
        start_new_session = os.name != "nt"
        if os.name == "nt":
            creationflags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        started = time.monotonic()
        start_time = _utc_now()
        timed_out = False
        return_code: int | None = None
        launch_error: str | None = None
        job = _WindowsJob()
        with stdout_path.open("wb") as stdout_stream, stderr_path.open("wb") as stderr_stream:
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_stream,
                    stderr=stderr_stream,
                    shell=False,
                    creationflags=creationflags,
                    start_new_session=start_new_session,
                )
                assigned = job.assign(process)
                try:
                    return_code = process.wait(timeout=float(timeout))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _kill_process_tree(process, job)
                    try:
                        return_code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        return_code = process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError) as exc:
                assigned = False
                error_number = getattr(exc, "errno", None)
                launch_error = f"{type(exc).__name__}(errno={error_number})"
            finally:
                job.close()
        result = _finish_run(
            repo_root=repo_root,
            project_root=project_root,
            plan_id=plan_id,
            plan=plan,
            plan_path=plan_path,
            plan_sha256=plan_sha256,
            authorization=authorization,
            argv=argv,
            cwd=cwd,
            timeout=timeout,
            run_id=run_id,
            run_root=run_root,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            started=started,
            start_time=start_time,
            timed_out=timed_out,
            return_code=return_code,
            launch_error=launch_error,
            assigned=bool(assigned),
            input_records=input_records,
            overrides=overrides,
            environment=environment,
        )
        with suppress(OSError):
            staging_root.rmdir()
        return result
    finally:
        execution_lock.release()


__all__ = ["execute_run"]
