"""Sparse human gates bound to content-addressed dependency closures."""

from __future__ import annotations

from collections.abc import Iterable

from .integrity import IntegrityError
from .models import (
    GateDecision,
    GateKind,
    GatePacket,
    GateRecord,
    ObjectRef,
    ReproductionLevel,
    new_id,
)
from .storage import LedgerStore


class GateError(ValueError):
    pass


class GateManager:
    """Create and validate Git-auditable human decisions.

    Gate records prove content consistency, not the cryptographic identity of the
    approver.  External signing can be layered on later without changing the
    dependency semantics.
    """

    def __init__(self, store: LedgerStore) -> None:
        self.store = store

    def _require_auditable_ledger(self) -> None:
        audit = self.store.audit()
        if not audit.ok:
            codes = ", ".join(issue.code for issue in audit.issues)
            raise GateError(f"ledger integrity failed: {codes}")

    def request(
        self,
        *,
        project_id: str,
        gate: GateKind,
        basis_commit: str,
        decisions_zh: Iterable[str],
        changes_zh: Iterable[str] = (),
        risks_zh: Iterable[str] = (),
        budget_zh: Iterable[str] = (),
        alternatives_zh: Iterable[str] = (),
        open_questions_zh: Iterable[str] = (),
        invalidation_conditions_zh: Iterable[str] = (),
        dependency_roots: Iterable[ObjectRef] = (),
        reproduction_level: ReproductionLevel | None = None,
    ) -> ObjectRef:
        self._require_auditable_ledger()
        roots = tuple(dependency_roots)
        closure = self.store.dependency_closure(roots)
        if not all(self.store.is_current_reference(item) for item in closure):
            raise GateError("cannot request a gate with superseded dependencies")
        source_issues = tuple(
            issue for item in closure for issue in self.store.source_binding_issues(item)
        )
        if source_issues:
            raise GateError("cannot request a gate with stale source bindings")
        packet = GatePacket(
            packet_id=new_id("gatepkt"),
            project_id=project_id,
            gate=gate,
            basis_commit=basis_commit,
            decisions_zh=tuple(decisions_zh),
            changes_zh=tuple(changes_zh),
            risks_zh=tuple(risks_zh),
            budget_zh=tuple(budget_zh),
            alternatives_zh=tuple(alternatives_zh),
            open_questions_zh=tuple(open_questions_zh),
            invalidation_conditions_zh=tuple(invalidation_conditions_zh),
            dependency_roots=roots,
            dependency_closure=closure,
            reproduction_level=reproduction_level,
        )
        return self.store.commit_object(
            project_id=project_id,
            object_type="gate.packet",
            object_id=packet.packet_id,
            payload=packet.model_dump(mode="json"),
            dependencies=closure,
            require_current=closure,
            require_source_current=closure,
            event_type="gate.requested",
            event_payload={"gate": gate.value, "packet_id": packet.packet_id},
        )

    def read_packet(self, packet_ref: ObjectRef) -> GatePacket:
        ledger_object = self.store.read_object(packet_ref)
        if ledger_object.object_type != "gate.packet":
            raise GateError("reference is not a gate packet")
        packet = GatePacket.model_validate(ledger_object.payload)
        if (
            packet.packet_id != ledger_object.object_id
            or packet.project_id != ledger_object.project_id
        ):
            raise GateError("gate packet payload does not match its ledger envelope")
        return packet

    def record(
        self,
        *,
        packet_ref: ObjectRef,
        decision: GateDecision,
        approver: str,
        current_basis_commit: str,
        accept_limited_reproduction: bool = False,
        note_zh: str = "",
    ) -> ObjectRef:
        self._require_auditable_ledger()
        packet = self.read_packet(packet_ref)
        if not self.store.is_current_reference(packet_ref):
            raise GateError("gate packet has been superseded")
        if packet.basis_commit != current_basis_commit:
            raise GateError("gate packet basis_commit is stale")
        current_closure = self.store.dependency_closure(packet.dependency_roots)
        if current_closure != packet.dependency_closure:
            raise GateError("gate packet dependency closure is stale")
        if not all(self.store.is_current_reference(item) for item in current_closure):
            raise GateError("gate packet has superseded dependencies")
        source_issues = tuple(
            issue
            for item in current_closure
            for issue in self.store.source_binding_issues(item)
        )
        if source_issues:
            raise GateError("gate packet has stale source bindings: " + ", ".join(source_issues))
        if (
            packet.gate is GateKind.G2
            and packet.reproduction_level
            in {ReproductionLevel.PARTIAL, ReproductionLevel.UNAVAILABLE}
            and decision is GateDecision.APPROVED
            and not accept_limited_reproduction
        ):
            raise GateError("G2 requires explicit acceptance of limited reproduction")
        record = GateRecord(
            record_id=new_id("gaterec"),
            project_id=packet.project_id,
            gate=packet.gate,
            packet_ref=packet_ref,
            packet_sha256=packet_ref.sha256,
            decision=decision,
            approver=approver,
            basis_commit=current_basis_commit,
            approved_dependencies=current_closure,
            accept_limited_reproduction=accept_limited_reproduction,
            note_zh=note_zh,
        )
        record_ref = self.store.commit_object(
            project_id=packet.project_id,
            object_type="gate.record",
            object_id=record.record_id,
            payload=record.model_dump(mode="json"),
            dependencies=(packet_ref, *current_closure),
            require_current=(packet_ref, *current_closure),
            require_source_current=current_closure,
            event_type="gate.recorded",
            event_payload={
                "gate": packet.gate.value,
                "packet_id": packet.packet_id,
                "record_id": record.record_id,
                "decision": decision.value,
            },
        )
        if self.store.state_path.exists():
            self.store.refresh_state_projection()
        return record_ref

    def validate(
        self,
        record_ref: ObjectRef,
        *,
        current_basis_commit: str,
    ) -> tuple[bool, tuple[str, ...]]:
        """Return validity and stable reasons; any dependency change fails closed."""

        reasons: list[str] = []
        if not self.store.audit().ok:
            return False, ("LEDGER_INTEGRITY_FAILED",)
        try:
            ledger_object = self.store.read_object(record_ref)
            if ledger_object.object_type != "gate.record":
                return False, ("NOT_GATE_RECORD",)
            record = GateRecord.model_validate(ledger_object.payload)
            packet = self.read_packet(record.packet_ref)
        except (IntegrityError, ValueError):
            return False, ("GATE_RECORD_INVALID",)
        if (
            record.record_id != ledger_object.object_id
            or record.project_id != ledger_object.project_id
            or record.project_id != packet.project_id
            or record.gate != packet.gate
        ):
            reasons.append("GATE_METADATA_MISMATCH")
        try:
            if not self.store.is_current_reference(record_ref):
                reasons.append("GATE_RECORD_SUPERSEDED")
            if not self.store.is_current_reference(record.packet_ref):
                reasons.append("GATE_PACKET_SUPERSEDED")
        except IntegrityError:
            reasons.append("GATE_CURRENCY_UNKNOWN")
        if record.decision is not GateDecision.APPROVED:
            reasons.append("NOT_APPROVED")
        if (
            record.basis_commit != current_basis_commit
            or packet.basis_commit != current_basis_commit
        ):
            reasons.append("BASIS_COMMIT_CHANGED")
        if record.packet_ref.sha256 != record.packet_sha256:
            reasons.append("PACKET_CHANGED")
        try:
            current_closure = self.store.dependency_closure(packet.dependency_roots)
            dependencies_current = all(
                self.store.is_current_reference(item) for item in current_closure
            )
            source_issues = tuple(
                issue
                for item in current_closure
                for issue in self.store.source_binding_issues(item)
            )
        except IntegrityError:
            reasons.append("DEPENDENCY_INVALID")
        else:
            if current_closure != packet.dependency_closure:
                reasons.append("PACKET_DEPENDENCIES_STALE")
            if current_closure != record.approved_dependencies:
                reasons.append("APPROVED_DEPENDENCIES_STALE")
            if not dependencies_current:
                reasons.append("DEPENDENCY_SUPERSEDED")
            reasons.extend(source_issues)
        if (
            packet.gate is GateKind.G2
            and packet.reproduction_level
            in {ReproductionLevel.PARTIAL, ReproductionLevel.UNAVAILABLE}
            and not record.accept_limited_reproduction
        ):
            reasons.append("LIMITED_REPRODUCTION_NOT_ACCEPTED")
        return not reasons, tuple(reasons)
