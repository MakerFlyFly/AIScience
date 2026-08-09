"""Crash-recoverable local storage for immutable objects and framed events."""

from __future__ import annotations

import ctypes
import json
import os
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from filelock import FileLock, Timeout

from .integrity import (
    IntegrityError,
    canonical_json,
    encode_frame,
    event_content_hash,
    read_event_file,
    sha256_bytes,
    sha256_file,
)
from .models import (
    PROJECT_ID_PATTERN,
    ArtifactStatus,
    EventRecord,
    IntegrityIssue,
    IntegrityReport,
    LedgerObject,
    ObjectRef,
    new_id,
    utc_now,
)
from .security import assert_safe_value


class ConcurrentWriteError(IntegrityError):
    pass


class SimulatedCrash(RuntimeError):
    """Fault-injection exception used by recovery tests."""


_T = TypeVar("_T")


def _flush_directory(path: Path) -> None:
    """Best-supported parent directory flush.

    POSIX exposes directory descriptors directly.  Windows needs a directory
    handle opened with ``FILE_FLAG_BACKUP_SEMANTICS``.  Some filesystems reject
    either operation, in which case the already-fsynced file and atomic replace
    still provide the strongest available guarantee.
    """

    if os.name != "nt":
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            return
        return

    try:
        kernel32 = ctypes.windll.kernel32
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000001 | 0x00000002 | 0x00000004,
            None,
            3,  # OPEN_EXISTING
            0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if handle not in (0, invalid_handle):
            kernel32.FlushFileBuffers(ctypes.c_void_p(handle))
            kernel32.CloseHandle(ctypes.c_void_p(handle))
    except (AttributeError, OSError, ValueError):
        return


def atomic_write(path: Path, data: bytes) -> None:
    """Fsync a sibling temporary file, replace, then best-effort flush its parent."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{new_id('tmp')}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _flush_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


class LedgerStore:
    """Single-writer local ledger rooted at one ``projects/<project_id>`` directory."""

    def __init__(self, project_dir: Path | str, *, lock_timeout: float = 10.0) -> None:
        self.project_dir = Path(project_dir).resolve()
        self.project_id = self.project_dir.name
        if not PROJECT_ID_PATTERN.fullmatch(self.project_id):
            raise ValueError("project directory name must be a valid project_id")
        self.ledger_dir = self.project_dir / "ledger"
        self.objects_dir = self.project_dir / "objects"
        self.events_path = self.ledger_dir / "events.log"
        self.journal_path = self.ledger_dir / "transaction.intent.json"
        self.quarantine_dir = self.ledger_dir / "quarantine"
        self.state_path = self.project_dir / "state.json"
        self.lock_path = self.ledger_dir / ".write.lock"
        self.lock_timeout = lock_timeout
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        self.objects_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._with_lock(self._recover_locked)

    def _with_lock(self, operation: Callable[[], _T]) -> _T:
        try:
            with FileLock(str(self.lock_path), timeout=self.lock_timeout):
                return operation()
        except Timeout as exc:
            raise ConcurrentWriteError("ledger writer lock timed out") from exc

    def _safe_project_path(self, relative: str) -> Path:
        normalized = relative.replace("\\", "/")
        candidate = (self.project_dir / normalized).resolve()
        try:
            candidate.relative_to(self.project_dir)
        except ValueError as exc:
            raise IntegrityError("ledger path escapes project directory") from exc
        return candidate

    def _object_relative_path(self, object_type: str, object_id: str, version: int) -> str:
        kind = object_type.replace(".", "/")
        return f"objects/{kind}/{object_id}.v{version}.json"

    def _quarantine_tail_locked(self) -> None:
        result = read_event_file(self.events_path)
        if not result.corrupt_tail:
            return
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        quarantine = self.quarantine_dir / f"events-tail-{stamp}.bin"
        atomic_write(quarantine, result.corrupt_tail)
        object_paths = set(self.objects_dir.rglob("*.json"))
        if result.valid_size == 0 and object_paths:
            pending_object: Path | None = None
            if self.journal_path.is_file():
                try:
                    intent = json.loads(self.journal_path.read_text(encoding="utf-8"))
                    pending_object = self._safe_project_path(str(intent["object_path"]))
                except (OSError, KeyError, TypeError, ValueError, IntegrityError):
                    pending_object = None
            pending = {pending_object} if pending_object is not None else set()
            if object_paths - pending:
                raise IntegrityError(
                    "event stream is invalid from the first frame while ledger objects exist; "
                    "refusing destructive recovery"
                )
        with self.events_path.open("r+b") as handle:
            handle.truncate(result.valid_size)
            handle.flush()
            os.fsync(handle.fileno())
        _flush_directory(self.events_path.parent)

    def _append_event_locked(self, event: EventRecord) -> None:
        frame = encode_frame(event)
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("ab") as handle:
            handle.write(frame)
            handle.flush()
            os.fsync(handle.fileno())
        _flush_directory(self.events_path.parent)

    def _last_event_hash_locked(self) -> str:
        result = read_event_file(self.events_path)
        if result.corrupt_tail:
            raise IntegrityError("event stream contains an invalid tail")
        return result.events[-1].event_hash if result.events else ""

    def _event_with_current_parent(self, event: EventRecord) -> EventRecord:
        data = event.model_dump(mode="json")
        data["previous_hash"] = self._last_event_hash_locked()
        data["event_hash"] = "0" * 64
        provisional = EventRecord.model_validate(data)
        data["event_hash"] = event_content_hash(provisional)
        return EventRecord.model_validate(data)

    def _recover_locked(self) -> None:
        self._quarantine_tail_locked()
        if not self.journal_path.exists():
            return
        try:
            intent = json.loads(self.journal_path.read_text(encoding="utf-8"))
            object_data = intent["object"]
            event_data = intent["event"]
            relative = str(intent["object_path"])
            object_path = self._safe_project_path(relative)
            expected = sha256_bytes(canonical_json(object_data) + b"\n")
            assert_safe_value(intent)
            ledger_object = LedgerObject.model_validate(object_data)
            event = EventRecord.model_validate(event_data)
            if event.event_hash != event_content_hash(event):
                raise ValueError("journal event hash is invalid")
            if event.object_ref is None:
                raise ValueError("journal event has no object reference")
            if event.object_ref.path != relative or event.object_ref.sha256 != expected:
                raise ValueError("journal object reference does not match object content")
            if ledger_object.anchor_event_id != event.event_id:
                raise ValueError("journal object/event mutual anchor is invalid")
            if (
                ledger_object.object_id != event.object_ref.object_id
                or ledger_object.object_type != event.object_ref.object_type
                or ledger_object.version != event.object_ref.version
                or ledger_object.project_id != event.project_id
                or ledger_object.project_id != self.project_id
            ):
                raise ValueError("journal object/event metadata differs")
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            IntegrityError,
        ) as exc:
            self._quarantine_journal_locked("invalid")
            raise IntegrityError("transaction journal is invalid and was quarantined") from exc

        if object_path.exists():
            if sha256_file(object_path) != expected:
                self._quarantine_journal_locked("conflict")
                raise IntegrityError("journal object conflicts with an existing immutable object")
        else:
            atomic_write(object_path, canonical_json(object_data) + b"\n")

        current_events = read_event_file(self.events_path).events
        matching = [item for item in current_events if item.event_id == event.event_id]
        if matching:
            if len(matching) != 1 or matching[0] != event:
                self._quarantine_journal_locked("event-conflict")
                raise IntegrityError("journal event id conflicts with the event ledger")
        else:
            event = self._event_with_current_parent(event)
            self._append_event_locked(event)
        self.journal_path.unlink(missing_ok=True)
        _flush_directory(self.journal_path.parent)

    def _quarantine_journal_locked(self, reason: str) -> None:
        if not self.journal_path.exists():
            return
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        destination = self.quarantine_dir / f"journal-{reason}-{stamp}.json"
        os.replace(self.journal_path, destination)
        _flush_directory(self.journal_path.parent)

    def recover(self) -> None:
        """Recover a pending transaction and quarantine a corrupt event suffix."""

        self._with_lock(self._recover_locked)

    def events(self) -> tuple[EventRecord, ...]:
        result = read_event_file(self.events_path)
        if result.corrupt_tail:
            raise IntegrityError("event stream has an invalid or torn suffix; call recover()")
        if any(event.project_id != self.project_id for event in result.events):
            raise IntegrityError("event stream contains another project's event")
        return result.events

    def read_object(self, reference: ObjectRef) -> LedgerObject:
        path = self._safe_project_path(reference.path)
        if not path.is_file():
            raise IntegrityError(f"referenced object is missing: {reference.path}")
        actual_hash = sha256_file(path)
        if actual_hash != reference.sha256:
            raise IntegrityError(f"referenced object hash mismatch: {reference.path}")
        try:
            ledger_object = LedgerObject.model_validate_json(path.read_bytes())
        except ValueError as exc:
            raise IntegrityError(f"object schema is invalid: {reference.path}") from exc
        if (
            ledger_object.object_id != reference.object_id
            or ledger_object.object_type != reference.object_type
            or ledger_object.version != reference.version
        ):
            raise IntegrityError(f"object reference metadata mismatch: {reference.path}")
        if ledger_object.project_id != self.project_id:
            raise IntegrityError(f"object belongs to another project: {reference.path}")
        return ledger_object

    def validate_references(self, references: Iterable[ObjectRef]) -> None:
        for reference in references:
            self.read_object(reference)

    def dependency_closure(self, roots: Iterable[ObjectRef]) -> tuple[ObjectRef, ...]:
        """Return a stable, validated transitive closure including every root."""

        pending = list(roots)
        found: dict[tuple[str, int], ObjectRef] = {}
        while pending:
            reference = pending.pop()
            key = (reference.object_id, reference.version)
            existing = found.get(key)
            if existing is not None:
                if existing != reference:
                    raise IntegrityError("conflicting references for one object version")
                continue
            ledger_object = self.read_object(reference)
            found[key] = reference
            pending.extend(ledger_object.dependencies)
        return tuple(
            sorted(found.values(), key=lambda ref: (ref.object_type, ref.object_id, ref.version))
        )

    def is_current_reference(self, reference: ObjectRef) -> bool:
        """Whether no later valid version of this lineage is anchored."""

        self.read_object(reference)
        later = (
            event.object_ref
            for event in self.events()
            if event.object_ref is not None
            and event.object_ref.object_id == reference.object_id
            and event.object_ref.object_type == reference.object_type
            and event.object_ref.version > reference.version
        )
        for candidate in later:
            try:
                self.read_object(candidate)
            except IntegrityError:
                # A corrupt later version makes currency unknowable; fail closed.
                return False
            return False
        return True

    def source_binding_issues(self, reference: ObjectRef) -> tuple[str, ...]:
        """Validate an artifact object against its current project-relative source.

        Objects without ``source_path``/``source_sha256`` are self-contained and do
        not need this additional check.  A later source-backed object of the same
        type invalidates the older binding even when a new random object ID was used.
        """

        ledger_object = self.read_object(reference)
        source_path = ledger_object.payload.get("source_path")
        source_hash = ledger_object.payload.get("source_sha256")
        if source_hash is None and reference.object_type == "research.protocol":
            source_hash = ledger_object.payload.get("sha256")
        if source_path is None and source_hash is None:
            return ()
        if not isinstance(source_path, str) or not isinstance(source_hash, str):
            return ("SOURCE_BINDING_INCOMPLETE",)
        try:
            path = self._safe_project_path(source_path)
        except IntegrityError:
            return ("SOURCE_PATH_INVALID",)
        issues: list[str] = []
        if not path.is_file():
            issues.append("SOURCE_MISSING")
        elif sha256_file(path) != source_hash:
            issues.append("SOURCE_CONTENT_CHANGED")

        anchor_seen = False
        for event in self.events():
            candidate_ref = event.object_ref
            if candidate_ref == reference:
                anchor_seen = True
                continue
            if not anchor_seen or candidate_ref is None:
                continue
            if candidate_ref.object_type != reference.object_type:
                continue
            try:
                candidate = self.read_object(candidate_ref)
            except IntegrityError:
                issues.append("SOURCE_SUCCESSOR_INVALID")
                continue
            candidate_source_hash = candidate.payload.get("source_sha256")
            if candidate_source_hash is None and candidate_ref.object_type == "research.protocol":
                candidate_source_hash = candidate.payload.get("sha256")
            if "source_path" in candidate.payload and isinstance(candidate_source_hash, str):
                singleton_types = {"delivery.manifest", "project.charter", "research.protocol"}
                same_source = candidate.payload.get("source_path") == source_path
                if reference.object_type in singleton_types or same_source:
                    issues.append("SOURCE_BINDING_SUPERSEDED")
                    break
        if not anchor_seen:
            issues.append("SOURCE_ANCHOR_MISSING")
        return tuple(dict.fromkeys(issues))

    def commit_object(
        self,
        *,
        project_id: str,
        object_type: str,
        payload: dict[str, Any],
        object_id: str | None = None,
        status: ArtifactStatus = ArtifactStatus.ACTIVE,
        dependencies: Iterable[ObjectRef] = (),
        supersedes: ObjectRef | None = None,
        event_type: str | None = None,
        event_payload: dict[str, Any] | None = None,
        require_current: Iterable[ObjectRef] = (),
        require_source_current: Iterable[ObjectRef] = (),
        fault_at: str | None = None,
    ) -> ObjectRef:
        """Atomically anchor an immutable object version and its event.

        ``fault_at`` accepts ``journal``, ``object``, or ``event`` and exists only
        for deterministic crash-recovery testing.
        """

        if fault_at not in {None, "journal", "object", "event"}:
            raise ValueError("fault_at must name a durable transaction phase")
        if project_id != self.project_id:
            raise ValueError("project_id must match the project directory name")
        dependency_tuple = tuple(dependencies)
        current_tuple = tuple(require_current)
        source_current_tuple = tuple(require_source_current)
        identity = object_id or new_id(object_type.split(".")[-1].replace("-", "_")[:15])
        version = 1 if supersedes is None else supersedes.version + 1

        def operation() -> ObjectRef:
            self._recover_locked()
            self.validate_references(dependency_tuple)
            for required in current_tuple:
                if not self.is_current_reference(required):
                    raise IntegrityError("required object version has been superseded")
            for required in source_current_tuple:
                source_issues = self.source_binding_issues(required)
                if source_issues:
                    raise IntegrityError(
                        "required source binding is stale: " + ", ".join(source_issues)
                    )
            if supersedes is not None:
                previous = self.read_object(supersedes)
                if previous.object_id != identity or previous.object_type != object_type:
                    raise IntegrityError("supersedes belongs to another object lineage")
                if not self.is_current_reference(supersedes):
                    raise IntegrityError("supersedes must be the current object version")

            event_id = new_id("evt")
            ledger_object = LedgerObject(
                project_id=project_id,
                object_id=identity,
                object_type=object_type,
                version=version,
                supersedes=supersedes,
                status=status,
                dependencies=dependency_tuple,
                anchor_event_id=event_id,
                payload=payload,
            )
            assert_safe_value(ledger_object)
            relative = self._object_relative_path(object_type, identity, version)
            object_path = self._safe_project_path(relative)
            object_bytes = canonical_json(ledger_object) + b"\n"
            object_hash = sha256_bytes(object_bytes)
            reference = ObjectRef(
                object_id=identity,
                object_type=object_type,
                version=version,
                path=relative,
                sha256=object_hash,
            )
            event_data: dict[str, Any] = {
                "schema_version": "1.0",
                "event_id": event_id,
                "project_id": project_id,
                "event_type": event_type or f"{object_type}.recorded",
                "timestamp": utc_now(),
                "previous_hash": self._last_event_hash_locked(),
                "object_ref": reference,
                "dependency_edges": dependency_tuple,
                "payload": event_payload or {},
                "event_hash": "0" * 64,
            }
            provisional = EventRecord.model_validate(event_data)
            event_data["event_hash"] = event_content_hash(provisional)
            event = EventRecord.model_validate(event_data)
            intent = {
                "schema_version": "1.0",
                "transaction_id": new_id("txn"),
                "phase": "prepared",
                "object_path": relative,
                "object": ledger_object.model_dump(mode="json"),
                "event": event.model_dump(mode="json"),
            }
            assert_safe_value(intent)
            atomic_write(self.journal_path, canonical_json(intent) + b"\n")
            if fault_at == "journal":
                raise SimulatedCrash("crash after durable intent")

            if object_path.exists():
                if sha256_file(object_path) != object_hash:
                    raise IntegrityError("immutable object path already exists with other content")
            else:
                atomic_write(object_path, object_bytes)
            intent["phase"] = "object_written"
            atomic_write(self.journal_path, canonical_json(intent) + b"\n")
            if fault_at == "object":
                raise SimulatedCrash("crash after object write")

            self._append_event_locked(event)
            intent["phase"] = "event_appended"
            atomic_write(self.journal_path, canonical_json(intent) + b"\n")
            if fault_at == "event":
                raise SimulatedCrash("crash after event append")
            self.journal_path.unlink(missing_ok=True)
            _flush_directory(self.journal_path.parent)
            return reference

        return self._with_lock(operation)

    def write_state(self, state: Any) -> None:
        """Validate and atomically write an event-rebuildable projection.

        A direct state write before the first project event is converted into an
        explicit ``project.state_seeded`` fact.  This supports controlled imports and
        tests without allowing an unanchored state snapshot.
        """

        from .state import ProjectState, StateProjectionError, rebuild_state

        data = state.model_dump(mode="json") if hasattr(state, "model_dump") else state
        if not isinstance(data, dict) or data.get("project_id") != self.project_id:
            raise ValueError("state project_id must match the project directory name")
        proposed = ProjectState.model_validate(data)
        assert_safe_value(proposed)
        events = self.events()
        has_origin = any(
            event.event_type in {"project.received", "project.state_seeded"} for event in events
        )
        if not has_origin:
            self.commit_object(
                project_id=self.project_id,
                object_type="project.state_seed",
                payload={"state": proposed.model_dump(mode="json")},
                event_type="project.state_seeded",
                event_payload={"state": proposed.model_dump(mode="json")},
            )
            events = self.events()
        expected = rebuild_state(self.project_id, events)
        proposed_semantics = proposed.model_dump(mode="json", exclude={"updated_at"})
        expected_semantics = expected.model_dump(mode="json", exclude={"updated_at"})
        if proposed_semantics != expected_semantics:
            raise StateProjectionError("proposed state differs from the event-derived projection")
        self._with_lock(
            lambda: atomic_write(self.state_path, canonical_json(expected) + b"\n")
        )

    def read_state(self) -> dict[str, Any] | None:
        if not self.state_path.exists():
            return None
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise IntegrityError("state projection is unreadable") from exc
        if not isinstance(value, dict):
            raise IntegrityError("state projection is not an object")
        if value.get("project_id") != self.project_id:
            raise IntegrityError("state projection belongs to another project")
        return value

    def require_valid_state(self) -> Any:
        """Return the typed state or fail closed on a missing/stale/tampered projection."""

        from .state import StateProjectionError, validate_state_projection

        persisted = self.read_state()
        if persisted is None:
            raise StateProjectionError("state.json is missing")
        return validate_state_projection(self.project_id, self.events(), persisted)

    def refresh_state_projection(self) -> Any:
        """Rebuild and durably replace ``state.json`` from the valid event stream."""

        from .state import rebuild_state

        expected = rebuild_state(self.project_id, self.events())
        assert_safe_value(expected)
        self._with_lock(
            lambda: atomic_write(self.state_path, canonical_json(expected) + b"\n")
        )
        return expected

    def audit(self) -> IntegrityReport:
        """Verify chain, mutual anchors, lineage, dependencies, and object orphans."""

        issues: list[IntegrityIssue] = []
        result = read_event_file(self.events_path)
        if result.corrupt_tail:
            issues.append(
                IntegrityIssue(
                    code="EVENT_TAIL_INVALID", message_zh="事件日志存在损坏或未完成尾帧。"
                )
            )
        anchored: dict[str, EventRecord] = {}
        seen_event_ids: set[str] = set()
        for event in result.events:
            if event.project_id != self.project_id:
                issues.append(
                    IntegrityIssue(
                        code="PROJECT_ID_MISMATCH",
                        message_zh="事件声明的项目与目录不一致。",
                    )
                )
            if event.event_id in seen_event_ids:
                issues.append(
                    IntegrityIssue(code="EVENT_ID_DUPLICATE", message_zh="事件 ID 重复。")
                )
            seen_event_ids.add(event.event_id)
            if event.object_ref is None:
                continue
            anchored[event.object_ref.path] = event
            try:
                ledger_object = self.read_object(event.object_ref)
                if ledger_object.anchor_event_id != event.event_id:
                    raise IntegrityError("object does not point back to its anchoring event")
                if ledger_object.project_id != event.project_id:
                    raise IntegrityError("object and event project ids differ")
                if tuple(ledger_object.dependencies) != tuple(event.dependency_edges):
                    raise IntegrityError("event dependency edges do not match object dependencies")
                self.validate_references(ledger_object.dependencies)
                if ledger_object.supersedes is not None:
                    self.read_object(ledger_object.supersedes)
            except IntegrityError as exc:
                issues.append(
                    IntegrityIssue(
                        code="OBJECT_ANCHOR_INVALID",
                        message_zh=str(exc),
                        path=event.object_ref.path,
                    )
                )

        object_paths = tuple(self.objects_dir.rglob("*.json")) if self.objects_dir.exists() else ()
        for path in object_paths:
            relative = path.relative_to(self.project_dir).as_posix()
            if relative not in anchored:
                issues.append(
                    IntegrityIssue(
                        code="OBJECT_ORPHAN",
                        message_zh="对象没有对应的锚定事件。",
                        path=relative,
                    )
                )
        if self.state_path.exists():
            try:
                self.require_valid_state()
            except (IntegrityError, ValueError) as exc:
                issues.append(
                    IntegrityIssue(
                        code="STATE_PROJECTION_INVALID",
                        message_zh=str(exc),
                        path="state.json",
                    )
                )
        return IntegrityReport(
            ok=not issues,
            event_count=len(result.events),
            object_count=len(object_paths),
            issues=tuple(issues),
        )
