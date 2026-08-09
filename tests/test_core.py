from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from aiscience.gates import GateError, GateManager
from aiscience.integrity import IntegrityError, canonical_json, read_event_file, sha256_object
from aiscience.models import (
    ClaimRecord,
    ClaimType,
    GateDecision,
    GateKind,
    GatePacket,
    HypothesisAction,
    HypothesisRecord,
    ObjectRef,
    ProjectStage,
    ReproductionLevel,
    SearchRecord,
    SupportStatus,
)
from aiscience.security import UnsafeContentError, assert_safe_text, redact_text, safe_digest_secret
from aiscience.state import GateState, ProjectState, TransitionError
from aiscience.storage import LedgerStore, SimulatedCrash


def make_store(tmp_path: Path, project_id: str = "study-01") -> LedgerStore:
    return LedgerStore(tmp_path / "projects" / project_id)


def test_canonical_json_is_stable_and_rejects_nonfinite() -> None:
    assert canonical_json({"中": 2, "a": [1, True]}) == canonical_json(
        {"a": [1, True], "中": 2}
    )
    assert sha256_object({"b": 2, "a": 1}) == sha256_object({"a": 1, "b": 2})
    with pytest.raises(ValueError):
        canonical_json({"value": float("nan")})


def test_models_require_utc_timestamps() -> None:
    with pytest.raises(ValidationError):
        GatePacket(
            packet_id="gatepkt_123456789abc",
            project_id="study-01",
            gate=GateKind.G0,
            created_at=datetime(2026, 1, 1),
            basis_commit="abcdef1",
            decisions_zh=("确认研究问题",),
        )


def test_english_change_marks_chinese_claim_translation_stale() -> None:
    canonical_text = "The updated result is positive."
    canonical_hash = __import__("hashlib").sha256(canonical_text.encode()).hexdigest()
    claim = ClaimRecord(
        claim_id="claim_123456789abc",
        project_id="study-01",
        canonical_text_en=canonical_text,
        reader_text_zh="旧版本结果为正。",
        claim_type=ClaimType.QUANTITATIVE,
        support_status=SupportStatus.SUPPORTED,
        canonical_version=2,
        canonical_text_sha256=canonical_hash,
        zh_based_on_version=1,
        zh_based_on_sha256="b" * 64,
    )
    assert claim.translation_stale
    with pytest.raises(ValidationError, match="canonical_text_sha256"):
        claim.model_copy(update={"canonical_text_en": "The result changed again."})


def test_hypothesis_lineage_requires_parent_rank_basis_and_elimination_reason() -> None:
    parent = ObjectRef(
        object_id="hyp_123456789abc",
        object_type="hypothesis",
        version=1,
        path="objects/hypothesis/hyp_123456789abc.v1.json",
        sha256="a" * 64,
    )
    with pytest.raises(ValidationError, match="parent"):
        HypothesisRecord(
            hypothesis_id="hyp_23456789abcd",
            project_id="study-01",
            action=HypothesisAction.EVOLVED,
            statement_en="The median is more robust.",
            statement_zh="中位数更稳健。",
        )
    ranked = HypothesisRecord(
        hypothesis_id="hyp_3456789abcde",
        project_id="study-01",
        action=HypothesisAction.RANKED,
        statement_en="The median is more robust.",
        statement_zh="中位数更稳健。",
        parent_refs=(parent,),
        relative_rank=1,
        rank_basis_zh="相对排名仅用于选择下一项证伪实验。",
    )
    assert ranked.parent_refs == (parent,)
    with pytest.raises(ValidationError, match="elimination reason"):
        HypothesisRecord(
            hypothesis_id="hyp_456789abcdef",
            project_id="study-01",
            action=HypothesisAction.ELIMINATED,
            statement_en=ranked.statement_en,
            statement_zh=ranked.statement_zh,
            parent_refs=(parent,),
        )


def test_typed_payloads_enforce_stable_ids_project_ids_and_utc() -> None:
    with pytest.raises(ValidationError):
        SearchRecord(
            record_id="bad",
            project_id="Not Safe",
            query="robust location estimators",
            tools_or_databases=("fixture",),
            queried_at=datetime(2026, 1, 1),
            ranking_method="fixture order",
            stop_condition="fixture exhausted",
            snapshot_summary_zh="本地测试快照",
        )


def test_state_machine_gates_iterations_and_rollback() -> None:
    state = ProjectState(project_id="study-01")
    with pytest.raises(TransitionError, match="G0"):
        state.transition(ProjectStage.CHARTER_LOCKED)
    state.transition(ProjectStage.CHARTER_LOCKED, approved_gates=(GateKind.G0,))
    state.transition(ProjectStage.DESIGNING)
    state.transition(ProjectStage.LITERATURE_REVIEW)
    state.transition(ProjectStage.DESIGNING)  # Explicitly supported design/literature loop.
    state.transition(ProjectStage.PROTOCOL_LOCKED)
    state.transition(ProjectStage.EXPERIMENTING)
    state.transition(ProjectStage.ANALYZING)
    state.transition(ProjectStage.EXPERIMENTING)  # Experiment/analysis loop.
    with pytest.raises(TransitionError):
        state.transition(ProjectStage.WRITING)
    state.transition(ProjectStage.ANALYZING)
    state.transition(ProjectStage.WRITING)
    state.transition(ProjectStage.REVIEWING)
    state.gates[GateKind.G0] = GateState(packet_id="p", record_id="r", approved=True)
    state.gates[GateKind.G2] = GateState(packet_id="p2", record_id="r2", approved=True)
    invalidated = state.transition(ProjectStage.DESIGNING, rollback=True)
    assert invalidated == (GateKind.G2,)
    assert not state.gates[GateKind.G0].stale
    assert state.gates[GateKind.G2].stale
    assert "downstream:all" in state.stale_artifact_ids


def test_object_event_mutual_anchor_and_tamper_detection(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    reference = store.commit_object(
        project_id="study-01", object_type="evidence.card", payload={"summary_zh": "支持假设"}
    )
    ledger_object = store.read_object(reference)
    event = store.events()[0]
    assert event.object_ref == reference
    assert ledger_object.anchor_event_id == event.event_id
    assert store.audit().ok

    path = store.project_dir / reference.path
    path.write_bytes(path.read_bytes().replace("支持".encode(), "反驳".encode()))
    report = store.audit()
    assert not report.ok
    assert any(issue.code == "OBJECT_ANCHOR_INVALID" for issue in report.issues)


def test_filelock_serializes_concurrent_writers(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    def write(index: int) -> None:
        store.commit_object(
            project_id="study-01",
            object_type="candidate",
            payload={"index": index},
        )

    with ThreadPoolExecutor(max_workers=6) as executor:
        list(executor.map(write, range(12)))
    assert len(store.events()) == 12
    assert store.audit().ok


def test_orphan_object_is_reported(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    reference = store.commit_object(
        project_id="study-01", object_type="source", payload={"title": "fixture"}
    )
    orphan = store.objects_dir / "source" / "orphan.v1.json"
    orphan.write_bytes((store.project_dir / reference.path).read_bytes())
    report = store.audit()
    assert not report.ok
    assert any(issue.code == "OBJECT_ORPHAN" and issue.path for issue in report.issues)


@pytest.mark.parametrize("fault_at", ["journal", "object", "event"])
def test_transaction_recovery_at_each_durable_phase(tmp_path: Path, fault_at: str) -> None:
    project_dir = tmp_path / "projects" / f"recovery-{fault_at}"
    store = LedgerStore(project_dir)
    with pytest.raises(SimulatedCrash):
        store.commit_object(
            project_id=f"recovery-{fault_at}",
            object_type="protocol",
            payload={"frozen": True},
            fault_at=fault_at,
        )
    recovered = LedgerStore(project_dir)
    assert len(recovered.events()) == 1
    assert recovered.audit().ok
    assert not recovered.journal_path.exists()


def test_torn_event_suffix_is_quarantined_on_startup(tmp_path: Path) -> None:
    project_dir = tmp_path / "projects" / "torn-log"
    store = LedgerStore(project_dir)
    store.commit_object(project_id="torn-log", object_type="source", payload={"title": "fixture"})
    valid_size = store.events_path.stat().st_size
    with store.events_path.open("ab") as handle:
        handle.write(b"00000040:{\"torn\":")
    assert read_event_file(store.events_path).corrupt_tail
    recovered = LedgerStore(project_dir)
    assert recovered.events_path.stat().st_size == valid_size
    assert len(list(recovered.quarantine_dir.glob("events-tail-*.bin"))) == 1
    assert recovered.audit().ok


def test_recovery_refuses_to_truncate_a_fully_corrupt_nonempty_ledger(tmp_path: Path) -> None:
    project_dir = tmp_path / "projects" / "chain-guard"
    store = LedgerStore(project_dir)
    store.commit_object(
        project_id="chain-guard",
        object_type="project.metadata",
        payload={"title": "preserve me"},
        event_type="project.received",
    )
    corrupted = store.events_path.read_bytes().replace(b"\n", b"\r\n")
    store.events_path.write_bytes(corrupted)

    with pytest.raises(IntegrityError, match="refusing destructive recovery"):
        LedgerStore(project_dir)

    assert store.events_path.read_bytes() == corrupted
    assert len(tuple(store.objects_dir.rglob("*.json"))) == 1


def test_invalid_journal_is_quarantined_fail_closed(tmp_path: Path) -> None:
    project_dir = tmp_path / "projects" / "bad-journal"
    store = LedgerStore(project_dir)
    store.journal_path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(Exception, match="journal"):
        LedgerStore(project_dir)
    assert list(store.quarantine_dir.glob("journal-invalid-*.json"))


def test_schema_invalid_journal_cannot_create_an_orphan(tmp_path: Path) -> None:
    project_dir = tmp_path / "projects" / "bad-schema-journal"
    store = LedgerStore(project_dir)
    invalid_intent = {
        "schema_version": "1.0",
        "transaction_id": "txn_123456789abc",
        "phase": "prepared",
        "object_path": "objects/source/source_123456789abc.v1.json",
        "object": {"schema_version": "1.0", "not": "a ledger object"},
        "event": {"schema_version": "1.0", "not": "an event"},
    }
    store.journal_path.write_bytes(canonical_json(invalid_intent) + b"\n")
    with pytest.raises(Exception, match="journal"):
        LedgerStore(project_dir)
    assert not (project_dir / invalid_intent["object_path"]).exists()
    assert list(store.quarantine_dir.glob("journal-invalid-*.json"))


def test_gate_becomes_stale_when_dependency_is_superseded(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    source_v1 = store.commit_object(
        project_id="study-01", object_type="source", payload={"title": "local fixture v1"}
    )
    gates = GateManager(store)
    packet_ref = gates.request(
        project_id="study-01",
        gate=GateKind.G0,
        basis_commit="abcdef1",
        decisions_zh=("确认目标与检索边界",),
        dependency_roots=(source_v1,),
    )
    record_ref = gates.record(
        packet_ref=packet_ref,
        decision=GateDecision.APPROVED,
        approver="human-reviewer",
        current_basis_commit="abcdef1",
    )
    valid, reasons = gates.validate(record_ref, current_basis_commit="abcdef1")
    assert valid and not reasons

    store.commit_object(
        project_id="study-01",
        object_type="source",
        object_id=source_v1.object_id,
        supersedes=source_v1,
        payload={"title": "local fixture v2"},
    )
    valid, reasons = gates.validate(record_ref, current_basis_commit="abcdef1")
    assert not valid
    assert "DEPENDENCY_SUPERSEDED" in reasons


def test_gate_becomes_stale_when_packet_is_superseded(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    gates = GateManager(store)
    packet_ref = gates.request(
        project_id="study-01",
        gate=GateKind.G0,
        basis_commit="abcdef1",
        decisions_zh=("批准原始研究合同",),
    )
    record_ref = gates.record(
        packet_ref=packet_ref,
        decision=GateDecision.APPROVED,
        approver="human-reviewer",
        current_basis_commit="abcdef1",
    )
    packet = gates.read_packet(packet_ref)
    store.commit_object(
        project_id="study-01",
        object_type="gate.packet",
        object_id=packet_ref.object_id,
        supersedes=packet_ref,
        payload=packet.model_copy(update={"decisions_zh": ("修改后的研究合同",)}).model_dump(
            mode="json"
        ),
    )
    valid, reasons = gates.validate(record_ref, current_basis_commit="abcdef1")
    assert not valid
    assert "GATE_PACKET_SUPERSEDED" in reasons


def test_stale_supersedes_fails_before_writing_journal(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    version_one = store.commit_object(
        project_id="study-01", object_type="hypothesis", payload={"text": "v1"}
    )
    store.commit_object(
        project_id="study-01",
        object_type="hypothesis",
        object_id=version_one.object_id,
        supersedes=version_one,
        payload={"text": "v2"},
    )
    with pytest.raises(Exception, match="current"):
        store.commit_object(
            project_id="study-01",
            object_type="hypothesis",
            object_id=version_one.object_id,
            supersedes=version_one,
            payload={"text": "branched v2"},
        )
    assert not store.journal_path.exists()


def test_gate_rejects_changed_commit_and_limited_reproduction(tmp_path: Path) -> None:
    gates = GateManager(make_store(tmp_path))
    packet_ref = gates.request(
        project_id="study-01",
        gate=GateKind.G2,
        basis_commit="abcdef1",
        decisions_zh=("确认主张与交付物",),
        reproduction_level=ReproductionLevel.PARTIAL,
    )
    with pytest.raises(GateError, match="basis_commit"):
        gates.record(
            packet_ref=packet_ref,
            decision=GateDecision.APPROVED,
            approver="human-reviewer",
            current_basis_commit="1234567",
        )
    with pytest.raises(GateError, match="limited reproduction"):
        gates.record(
            packet_ref=packet_ref,
            decision=GateDecision.APPROVED,
            approver="human-reviewer",
            current_basis_commit="abcdef1",
        )


@pytest.mark.parametrize(
    "unsafe",
    [
        "contact alice@example.org",
        "api_key=sk-proj-abcdefghijklmnopqrstuv",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "身份证 11010519491231002X",
    ],
)
def test_sensitive_content_is_detected_and_redacted_without_digest(unsafe: str) -> None:
    with pytest.raises(UnsafeContentError):
        assert_safe_text(unsafe)
    redacted, kinds = redact_text(unsafe)
    assert kinds
    assert unsafe not in redacted
    assert "[REDACTED:" in redacted
    with pytest.raises(UnsafeContentError):
        safe_digest_secret("short-password", sensitive=True)


def test_ledger_refuses_pii_in_tracked_payload(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(UnsafeContentError):
        store.commit_object(
            project_id="study-01",
            object_type="note",
            payload={"contact": "alice@example.org"},
        )
    assert not store.events()
    assert not store.journal_path.exists()


def test_store_binds_records_and_state_to_project_directory(tmp_path: Path) -> None:
    store = make_store(tmp_path, "alpha-study")
    with pytest.raises(ValueError, match="project_id"):
        store.commit_object(project_id="beta-study", object_type="note", payload={"ok": True})
    with pytest.raises(ValueError, match="project_id"):
        store.write_state(ProjectState(project_id="beta-study"))
    assert not store.events()


@pytest.mark.parametrize("key", ["password", "api_key", "token"])
def test_ledger_refuses_quoted_json_secret_keys(tmp_path: Path, key: str) -> None:
    store = make_store(tmp_path, f"secret-{key.replace('_', '-')}")
    with pytest.raises(UnsafeContentError):
        store.commit_object(
            project_id=f"secret-{key.replace('_', '-')}",
            object_type="note",
            payload={key: "correcthorsebatterystaple"},
        )
