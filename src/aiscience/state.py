"""Project workflow state machine and deterministic state projection."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import SCHEMA_VERSION, EventRecord, GateKind, ProjectStage, ProjectStatus, utc_now


class TransitionError(ValueError):
    pass


class StateProjectionError(ValueError):
    """Persisted state is missing, invalid, or differs from the event projection."""


_FORWARD: dict[ProjectStage, frozenset[ProjectStage]] = {
    ProjectStage.RECEIVED: frozenset({ProjectStage.CHARTER_LOCKED}),
    ProjectStage.CHARTER_LOCKED: frozenset({ProjectStage.DESIGNING}),
    ProjectStage.DESIGNING: frozenset(
        {ProjectStage.LITERATURE_REVIEW, ProjectStage.PROTOCOL_LOCKED}
    ),
    ProjectStage.LITERATURE_REVIEW: frozenset(
        {ProjectStage.DESIGNING, ProjectStage.PROTOCOL_LOCKED}
    ),
    ProjectStage.PROTOCOL_LOCKED: frozenset({ProjectStage.EXPERIMENTING}),
    ProjectStage.EXPERIMENTING: frozenset({ProjectStage.ANALYZING}),
    ProjectStage.ANALYZING: frozenset({ProjectStage.EXPERIMENTING, ProjectStage.WRITING}),
    ProjectStage.WRITING: frozenset({ProjectStage.REVIEWING}),
    ProjectStage.REVIEWING: frozenset({ProjectStage.DELIVERY_READY}),
    ProjectStage.DELIVERY_READY: frozenset({ProjectStage.DELIVERED}),
    ProjectStage.DELIVERED: frozenset(),
}

_ORDER = tuple(ProjectStage)
_ORDER_INDEX = {stage: index for index, stage in enumerate(_ORDER)}


class GateState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    packet_id: str
    record_id: str
    approved: bool
    stale: bool = False


class ProjectState(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    project_id: str
    stage: ProjectStage = ProjectStage.RECEIVED
    status: ProjectStatus = ProjectStatus.ACTIVE
    revision: int = Field(default=0, ge=0)
    updated_at: datetime = Field(default_factory=utc_now)
    gates: dict[GateKind, GateState] = Field(default_factory=dict)
    stale_artifact_ids: set[str] = Field(default_factory=set)

    @field_validator("updated_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("updated_at must be timezone-aware")
        return value.astimezone(UTC)

    def transition(
        self,
        target: ProjectStage,
        *,
        approved_gates: Iterable[GateKind] = (),
        rollback: bool = False,
    ) -> tuple[GateKind, ...]:
        """Move to ``target`` and return gates invalidated by this change."""

        if self.status not in {ProjectStatus.ACTIVE, ProjectStatus.PARTIAL}:
            raise TransitionError(f"project status {self.status} cannot transition")
        if target == self.stage:
            raise TransitionError("source and target stages are identical")
        # GateState is an event projection, not an authorization source.  Only the
        # caller's freshly ledger-validated approvals may unlock a transition.
        allowed_gates = set(approved_gates)
        if target is ProjectStage.CHARTER_LOCKED and GateKind.G0 not in allowed_gates:
            raise TransitionError("G0 approval is required to lock the research charter")
        if target is ProjectStage.DELIVERY_READY and GateKind.G2 not in allowed_gates:
            raise TransitionError("G2 approval is required for delivery_ready")

        is_backward = _ORDER_INDEX[target] < _ORDER_INDEX[self.stage]
        is_defined_iteration = target in _FORWARD[self.stage]
        is_general_rollback = is_backward and not is_defined_iteration
        if is_general_rollback:
            if not rollback:
                raise TransitionError("backward transitions must be explicit rollbacks")
            # Review findings can return the project to the earliest affected phase.
            if self.stage not in {
                ProjectStage.REVIEWING,
                ProjectStage.DELIVERY_READY,
            }:
                raise TransitionError("only review/delivery stages may perform a general rollback")
        elif not is_defined_iteration:
            raise TransitionError(f"illegal transition: {self.stage} -> {target}")

        invalidated: list[GateKind] = []
        if is_backward:
            for kind, gate_state in self.gates.items():
                affected = target is ProjectStage.RECEIVED or kind is not GateKind.G0
                if affected and not gate_state.stale:
                    gate_state.stale = True
                    invalidated.append(kind)
            self.stale_artifact_ids.add("downstream:all")
        self.stage = target
        self.revision += 1
        self.updated_at = utc_now()
        return tuple(sorted(invalidated, key=str))

    def set_status(self, status: ProjectStatus) -> None:
        if self.status in {ProjectStatus.SUPERSEDED, ProjectStatus.WITHDRAWN}:
            raise TransitionError(f"terminal project status {self.status} cannot change")
        self.status = status
        self.revision += 1
        self.updated_at = utc_now()


def rebuild_state(project_id: str, events: Iterable[EventRecord]) -> ProjectState:
    """Rebuild the state projection from valid event facts."""

    state = ProjectState(project_id=project_id)
    approved: set[GateKind] = set()
    origin_seen = False
    for event in events:
        if event.project_id != project_id:
            raise TransitionError("event project does not match projection")
        if event.event_type == "project.state_seeded":
            if origin_seen:
                raise StateProjectionError("project state origin is duplicated")
            try:
                seeded = ProjectState.model_validate(event.payload["state"])
            except (KeyError, ValueError) as exc:
                raise StateProjectionError("project state seed is invalid") from exc
            if seeded.project_id != project_id:
                raise StateProjectionError("project state seed belongs to another project")
            state = seeded
            state.updated_at = event.timestamp
            approved = {
                kind
                for kind, gate_state in state.gates.items()
                if gate_state.approved and not gate_state.stale
            }
            origin_seen = True
        elif event.event_type == "gate.recorded":
            gate = GateKind(str(event.payload["gate"]))
            is_approved = event.payload.get("decision") == "approved"
            if is_approved:
                approved.add(gate)
            else:
                approved.discard(gate)
            state.gates[gate] = GateState(
                packet_id=str(event.payload["packet_id"]),
                record_id=str(event.payload["record_id"]),
                approved=is_approved,
                stale=False,
            )
            state.updated_at = event.timestamp
        elif event.event_type == "gate.invalidated":
            gate = GateKind(str(event.payload["gate"]))
            if gate in state.gates:
                state.gates[gate].stale = True
            approved.discard(gate)
            state.updated_at = event.timestamp
        elif event.event_type == "project.transitioned":
            state.transition(
                ProjectStage(str(event.payload["target"])),
                approved_gates=approved,
                rollback=bool(event.payload.get("rollback", False)),
            )
            approved = {
                kind
                for kind, gate_state in state.gates.items()
                if gate_state.approved and not gate_state.stale
            }
            state.updated_at = event.timestamp
        elif event.event_type == "project.demo_transitioned":
            if not project_id.startswith("demo-") or event.payload.get("demo_only") is not True:
                raise TransitionError("demo transition is not isolated to a demo fixture")
            state.transition(
                ProjectStage(str(event.payload["target"])),
                approved_gates=(GateKind.G0, GateKind.G2),
                rollback=False,
            )
            state.updated_at = event.timestamp
        elif event.event_type == "project.status_changed":
            state.set_status(ProjectStatus(str(event.payload["status"])))
            state.updated_at = event.timestamp
        elif event.event_type == "project.received":
            if origin_seen:
                raise StateProjectionError("project state origin is duplicated")
            state.updated_at = event.timestamp
            origin_seen = True
    return state


def validate_state_projection(
    project_id: str,
    events: Iterable[EventRecord],
    persisted: dict[str, Any],
) -> ProjectState:
    """Fail closed unless ``persisted`` exactly matches the event-derived state."""

    try:
        actual = ProjectState.model_validate(persisted)
        expected = rebuild_state(project_id, events)
    except ValueError as exc:
        raise StateProjectionError("state projection cannot be rebuilt") from exc
    if actual.model_dump(mode="json") != expected.model_dump(mode="json"):
        raise StateProjectionError("state.json differs from the event-derived projection")
    return expected
