from __future__ import annotations

import json
from pathlib import Path

import pytest

from aiscience.gates import GateManager
from aiscience.integrity import IntegrityError
from aiscience.models import GateDecision, GateKind, ObjectRef, ProjectStage
from aiscience.scaffold import record_artifact
from aiscience.state import ProjectState, StateProjectionError, TransitionError
from aiscience.storage import LedgerStore


def _initialized_store(tmp_path: Path, project_id: str = "guard-study") -> LedgerStore:
    project = tmp_path / "projects" / project_id
    store = LedgerStore(project)
    store.commit_object(
        project_id=project_id,
        object_type="project.metadata",
        payload={"title": "projection fixture"},
        event_type="project.received",
    )
    store.write_state(ProjectState(project_id=project_id))
    return store


def _approve(
    store: LedgerStore,
    gate: GateKind,
    dependency: ObjectRef,
    basis: str = "abcdef1",
):
    manager = GateManager(store)
    packet_ref = manager.request(
        project_id=store.project_id,
        gate=gate,
        basis_commit=basis,
        decisions_zh=("确认待审制品",),
        dependency_roots=(dependency,),
    )
    record_ref = manager.record(
        packet_ref=packet_ref,
        decision=GateDecision.APPROVED,
        approver="human-reviewer",
        current_basis_commit=basis,
    )
    return manager, record_ref


def test_state_projection_detects_manual_tampering_and_can_rebuild(tmp_path: Path) -> None:
    store = _initialized_store(tmp_path)
    valid = store.require_valid_state()
    assert valid.stage is ProjectStage.RECEIVED

    tampered = store.read_state()
    assert tampered is not None
    tampered["stage"] = ProjectStage.WRITING.value
    store.state_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(StateProjectionError, match="differs"):
        store.require_valid_state()
    report = store.audit()
    assert not report.ok
    assert any(issue.code == "STATE_PROJECTION_INVALID" for issue in report.issues)

    repaired = store.refresh_state_projection()
    assert repaired.stage is ProjectStage.RECEIVED
    assert store.require_valid_state() == repaired


def test_demo_transition_event_is_rejected_outside_demo_namespace(tmp_path: Path) -> None:
    store = _initialized_store(tmp_path)
    store.commit_object(
        project_id=store.project_id,
        object_type="project.demo_transition",
        payload={"target": "charter_locked", "demo_only": True},
        event_type="project.demo_transitioned",
        event_payload={"target": "charter_locked", "demo_only": True},
    )

    with pytest.raises(TransitionError, match="not isolated"):
        store.refresh_state_projection()


def test_state_gate_cache_cannot_authorize_without_fresh_validation(tmp_path: Path) -> None:
    state = ProjectState(project_id="guard-study")
    # Even a syntactically populated state cache is not an authorization source.
    from aiscience.state import GateState

    state.gates[GateKind.G0] = GateState(
        packet_id="gatepkt_123456789abc",
        record_id="gaterec_123456789abc",
        approved=True,
    )
    with pytest.raises(Exception, match="G0"):
        state.transition(ProjectStage.CHARTER_LOCKED)


def test_g0_invalidates_when_source_content_changes_or_is_rerecorded(tmp_path: Path) -> None:
    store = _initialized_store(tmp_path, "g0-study")
    source = store.project_dir / "project.yaml"
    source.write_text("title: original\n", encoding="utf-8")
    artifact_ref = record_artifact(
        store.project_dir,
        store.project_id,
        source=source,
        object_type="project.config",
    )
    manager, record_ref = _approve(store, GateKind.G0, artifact_ref)
    assert manager.validate(record_ref, current_basis_commit="abcdef1") == (True, ())

    source.write_text("title: changed\n", encoding="utf-8")
    valid, reasons = manager.validate(record_ref, current_basis_commit="abcdef1")
    assert not valid
    assert "SOURCE_CONTENT_CHANGED" in reasons

    # Re-recording uses a new random object ID; the old approval must still expire.
    record_artifact(
        store.project_dir,
        store.project_id,
        source=source,
        object_type="project.config",
    )
    valid, reasons = manager.validate(record_ref, current_basis_commit="abcdef1")
    assert not valid
    assert "SOURCE_BINDING_SUPERSEDED" in reasons


def test_g1_invalidates_when_new_artifact_path_replaces_old_one(tmp_path: Path) -> None:
    store = _initialized_store(tmp_path, "g1-study")
    old_source = store.project_dir / "experiments" / "protocol-old.md"
    old_source.parent.mkdir(parents=True)
    old_source.write_text("frozen protocol v1\n", encoding="utf-8")
    artifact_ref = record_artifact(
        store.project_dir,
        store.project_id,
        source=old_source,
        object_type="research.protocol",
    )
    manager, record_ref = _approve(store, GateKind.G1, artifact_ref)

    new_source = store.project_dir / "experiments" / "protocol-current.md"
    new_source.write_text("frozen protocol v2\n", encoding="utf-8")
    record_artifact(
        store.project_dir,
        store.project_id,
        source=new_source,
        object_type="research.protocol",
    )
    valid, reasons = manager.validate(record_ref, current_basis_commit="abcdef1")
    assert not valid
    assert "SOURCE_BINDING_SUPERSEDED" in reasons


def test_gate_record_fails_closed_if_source_changed_before_human_record(tmp_path: Path) -> None:
    store = _initialized_store(tmp_path, "record-guard")
    source = store.project_dir / "project.yaml"
    source.write_text("title: reviewed\n", encoding="utf-8")
    artifact_ref = record_artifact(
        store.project_dir,
        store.project_id,
        source=source,
        object_type="project.config",
    )
    manager = GateManager(store)
    packet_ref = manager.request(
        project_id=store.project_id,
        gate=GateKind.G0,
        basis_commit="abcdef1",
        decisions_zh=("确认研究合同",),
        dependency_roots=(artifact_ref,),
    )
    source.write_text("title: changed before approval\n", encoding="utf-8")
    with pytest.raises((ValueError, IntegrityError), match="source"):
        manager.record(
            packet_ref=packet_ref,
            decision=GateDecision.APPROVED,
            approver="human-reviewer",
            current_basis_commit="abcdef1",
        )
