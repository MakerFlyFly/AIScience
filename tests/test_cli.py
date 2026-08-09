from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from pypdf import PdfWriter
from typer.testing import CliRunner

from aiscience.cli import (
    _central_g2_approval,
    _missing_research_contract,
    _valid_gate_records,
    app,
)
from aiscience.delivery import prepare_package
from aiscience.demo import create_demo
from aiscience.gates import GateManager
from aiscience.models import (
    ExperimentRecord,
    GateDecision,
    GateKind,
    ObjectRef,
    ProjectStage,
    ReproductionLevel,
)
from aiscience.scaffold import find_object_ref, record_artifact
from aiscience.state import ProjectState
from aiscience.storage import LedgerStore


def _git_repo(path: Path) -> str:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"], cwd=path, check=True
    )
    (path / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "add", "seed.txt"], cwd=path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "seed"], cwd=path, check=True, capture_output=True
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _approved_gate(store: LedgerStore, project_id: str, gate: GateKind, basis: str) -> None:
    manager = GateManager(store)
    packet_ref = manager.request(
        project_id=project_id,
        gate=gate,
        basis_commit=basis,
        decisions_zh=("确认受控测试决策",),
    )
    manager.record(
        packet_ref=packet_ref,
        decision=GateDecision.APPROVED,
        approver="human-test-reviewer",
        current_basis_commit=basis,
    )


def test_research_contract_requires_non_default_experiment_boundaries() -> None:
    config = {
        "defaults": {
            "paid_budget": 0,
            "gpu_authorized": False,
            "experiment_concurrency": 1,
        },
        "research_contract": {
            "success_criteria": ["主要结果可复查"],
            "scope_in": ["合成数据"],
            "scope_out": ["临床结论"],
            "confidentiality": "公开合成数据",
            "data_license_ethics": "无个人数据",
            "deliverables": ["双语论文"],
            "public_query_boundary": "仅公开只读来源",
        },
        "limits": {
            "time_hours": None,
            "max_runs": 10,
            "disk_mib": 512,
            "data_scope": "仅项目内合成输入",
        },
    }
    assert _missing_research_contract(config) == ["limits.time_hours"]
    config["limits"]["time_hours"] = 2
    assert _missing_research_contract(config) == []


def test_demo_rejection_uses_json_envelope_and_preserves_formal_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    formal = tmp_path / "projects" / "formal-study"
    formal.mkdir(parents=True)
    sentinel = formal / "sentinel.txt"
    sentinel.write_text("preserve\n", encoding="utf-8")
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)

    result = CliRunner().invoke(
        app, ["demo", "--project-id", "formal-study", "--overwrite"]
    )

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["errors"][0]["code"] == "DEMO_INPUT_REJECTED"
    assert sentinel.read_text(encoding="utf-8") == "preserve\n"


def test_validate_corrupt_ledger_uses_integrity_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    store = LedgerStore(project)
    store.commit_object(
        project_id="study-01",
        object_type="project.metadata",
        payload={"title": "fixture"},
        event_type="project.received",
    )
    store.events_path.write_bytes(store.events_path.read_bytes().replace(b"\n", b"\r\n"))
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)

    result = CliRunner().invoke(app, ["validate", "study-01", "--strict"])

    assert result.exit_code == 5
    assert json.loads(result.output)["errors"][0]["code"] == "LEDGER_INTEGRITY_UNAVAILABLE"


def test_gate_request_rejects_unrelated_g0_artifact_and_unbound_g1_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    project.mkdir(parents=True)
    (project / "project.yaml").write_text("project_id: study-01\n", encoding="utf-8")
    (project / "other.yaml").write_text("project_id: study-01\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "gate candidates"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)
    runner = CliRunner()

    g0 = runner.invoke(
        app,
        [
            "gate",
            "request",
            "study-01",
            "G0",
            "--decision",
            "确认合同",
            "--artifact",
            "other.yaml",
        ],
    )
    g1 = runner.invoke(
        app, ["gate", "request", "study-01", "G1", "--decision", "确认条件执行"]
    )

    assert g0.exit_code == 2
    assert json.loads(g0.output)["errors"][0]["code"] == "G0_ARTIFACT_MISMATCH"
    assert g1.exit_code == 2
    assert json.loads(g1.output)["errors"][0]["code"] == "G1_PLAN_BINDING_INVALID"


def test_g1_request_binds_the_selected_plan_and_its_protocol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    protocol = project / "design" / "protocol.md"
    plan = project / "experiments" / "plans" / "plan-01.json"
    protocol.parent.mkdir(parents=True)
    plan.parent.mkdir(parents=True)
    protocol.write_text("frozen protocol\n", encoding="utf-8")
    plan.write_text(
        json.dumps(
            {
                "plan_id": "plan-01",
                "protocol": {
                    "path": "design/protocol.md",
                    "sha256": hashlib.sha256(protocol.read_bytes()).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "G1 candidate"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)

    result = CliRunner().invoke(
        app,
        [
            "gate",
            "request",
            "study-01",
            "G1",
            "--decision",
            "确认计划与协议",
            "--plan-id",
            "plan-01",
        ],
    )

    assert result.exit_code == 0, result.output
    packet_ref = ObjectRef.model_validate(json.loads(result.output)["data"]["packet_ref"])
    packet = GateManager(LedgerStore(project)).read_packet(packet_ref)
    assert {reference.object_type for reference in packet.dependency_roots} == {
        "experiment.plan",
        "research.protocol",
    }


def test_failed_run_uses_errors_array(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    project.mkdir(parents=True)
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)
    monkeypatch.setattr(
        "aiscience.runner.execute_run",
        lambda *_args: {
            "status": "failed",
            "failure_kind": "precondition",
            "error_code": "G0_REQUIRED",
            "message": "缺少 G0。",
        },
    )

    result = CliRunner().invoke(app, ["run", "execute", "study-01", "plan-01"])

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["errors"] == [{"code": "G0_REQUIRED", "message_zh": "缺少 G0。"}]


def test_cli_records_and_versions_a_typed_research_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    candidate = project / "candidates" / "source.json"
    candidate.parent.mkdir(parents=True)
    payload = {
        "schema_version": "1.0",
        "source_id": "source_123456789abc",
        "project_id": "study-01",
        "title": "Local robustness fixture",
        "local_fixture": True,
        "version_label": "fixture-v1",
        "access_level": "metadata_only",
        "license": "CC0-1.0",
    }
    candidate.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    first = runner.invoke(
        app,
        ["ledger", "record", "study-01", "source", "candidates/source.json"],
    )
    assert first.exit_code == 0, first.output
    payload["title"] = "Corrected local robustness fixture"
    payload["version_label"] = "fixture-v2"
    candidate.write_text(json.dumps(payload), encoding="utf-8")
    second = runner.invoke(
        app,
        [
            "ledger",
            "record",
            "study-01",
            "source",
            "candidates/source.json",
            "--supersedes",
            "source_123456789abc",
        ],
    )
    assert second.exit_code == 0, second.output
    reference = find_object_ref(project, "source_123456789abc")
    assert reference.version == 2
    assert LedgerStore(project).audit().ok


def test_cli_can_record_typed_protocol_and_review_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    candidates = project / "candidates"
    candidates.mkdir(parents=True)
    protocol_source = project / "design" / "protocol.md"
    protocol_source.parent.mkdir(parents=True)
    protocol_source.write_text("frozen protocol\n", encoding="utf-8")
    protocol_id = "protocol_123456789abc"
    protocol_payload = {
        "schema_version": "1.0",
        "protocol_id": protocol_id,
        "project_id": "study-01",
        "source_path": "design/protocol.md",
        "sha256": hashlib.sha256(protocol_source.read_bytes()).hexdigest(),
        "frozen": True,
        "demo_only": False,
    }
    (candidates / "protocol.json").write_text(json.dumps(protocol_payload), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    protocol_result = runner.invoke(
        app,
        ["ledger", "record", "study-01", "research.protocol", "candidates/protocol.json"],
    )
    assert protocol_result.exit_code == 0, protocol_result.output

    protocol_ref = find_object_ref(project, protocol_id)
    review_payload = {
        "schema_version": "1.0",
        "review_id": "review_123456789abc",
        "project_id": "study-01",
        "status": "passed_for_delivery",
        "risk_counts": {"high": 0, "medium": 0, "low": 0},
        "covered_refs": [protocol_ref.model_dump(mode="json")],
        "findings": [],
        "reproducibility": "full",
        "demo_only": False,
    }
    (candidates / "review.json").write_text(json.dumps(review_payload), encoding="utf-8")
    review_result = runner.invoke(
        app,
        [
            "ledger",
            "record",
            "study-01",
            "review.report",
            "candidates/review.json",
            "--depends-on",
            protocol_id,
        ],
    )
    assert review_result.exit_code == 0, review_result.output
    assert find_object_ref(project, "review_123456789abc").object_type == "review.report"


def test_transition_rejects_tampered_projection_before_appending_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    store = LedgerStore(project)
    store.write_state(ProjectState(project_id="study-01").model_dump(mode="json"))
    (project / "project.yaml").write_text("g1_required: false\n", encoding="utf-8")
    tampered = store.read_state()
    assert isinstance(tampered, dict)
    tampered["stage"] = "reviewing"
    store.state_path.write_text(json.dumps(tampered), encoding="utf-8")
    before = len(store.events())
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["transition", "study-01", "charter_locked"])

    assert result.exit_code != 0
    assert json.loads(result.output)["errors"][0]["code"] == "STATE_PROJECTION_INVALID"
    assert len(store.events()) == before


def test_cli_anchors_run_record_to_its_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    basis = _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    plan = project / "experiments" / "plans" / "plan-01.json"
    plan.parent.mkdir(parents=True)
    plan.write_text('{"plan_id":"plan-01","argv":["python","-V"]}\n', encoding="utf-8")
    protocol = project / "design" / "protocol.md"
    protocol.parent.mkdir(parents=True)
    protocol.write_text("frozen protocol\n", encoding="utf-8")
    protocol_sha = hashlib.sha256(protocol.read_bytes()).hexdigest()
    store = LedgerStore(project)
    protocol_ref = store.commit_object(
        project_id="study-01",
        object_type="research.protocol",
        payload={"source_path": "design/protocol.md", "sha256": protocol_sha, "frozen": True},
        event_type="research.protocol_locked",
    )

    def fake_execute(_repo: Path, _project_id: str, _plan_id: str) -> dict[str, object]:
        run_id = "run_123456789abc"
        run_path = project / "runs" / run_id / "run.json"
        run_path.parent.mkdir(parents=True)
        run_path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "run_id": run_id,
                    "status": "completed",
                    "basis_commit": basis,
                    "argv": ["python", "-V"],
                }
            ),
            encoding="utf-8",
        )
        return {
            "run_id": run_id,
            "status": "completed",
            "basis_commit": basis,
            "authorization": {
                "protocol": {"path": "design/protocol.md", "sha256": protocol_sha},
                "scripts": [],
                "inputs": [],
            },
            "argv": ["python", "-V"],
            "seeds": {},
            "hardware": {"kind": "test"},
            "environment": {"fingerprint_sha256": "0" * 64},
            "logs": {},
            "outputs": [],
            "enforcement": {"shell_disabled": "hard", "network": "observed_only"},
            "reproducibility": "full",
        }

    monkeypatch.setattr("aiscience.runner.execute_run", fake_execute)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["run", "execute", "study-01", "plan-01"])
    assert result.exit_code == 0, result.output
    events = store.events()
    assert [event.object_ref.object_type for event in events if event.object_ref] == [
        "research.protocol",
        "experiment.plan",
        "experiment.run_record",
        "experiment",
    ]
    assert set(events[-1].dependency_edges) == {
        events[1].object_ref,
        events[2].object_ref,
        protocol_ref,
    }
    assert events[-1].object_ref is not None
    assert events[-1].object_ref.object_type == "experiment"
    assert store.audit().ok


def test_public_cli_records_a_real_demo_run_as_typed_experiment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    repository = Path(__file__).resolve().parents[1]
    shutil.copy2(repository / ".gitattributes", tmp_path / ".gitattributes")
    shutil.copy2(repository / ".gitignore", tmp_path / ".gitignore")
    source_template = (
        repository
        / ".agents"
        / "skills"
        / "research-orchestrator"
        / "assets"
        / "project-template"
    )
    target = tmp_path / ".agents" / "skills" / "research-orchestrator" / "assets"
    target.mkdir(parents=True)
    shutil.copytree(source_template, target / "project-template")

    def fake_build(repo: Path, project_id: str) -> dict[str, object]:
        build = repo / "projects" / project_id / "paper" / "build"
        build.mkdir(parents=True, exist_ok=True)
        for language in ("en", "zh"):
            writer = PdfWriter()
            writer.add_blank_page(width=72, height=72)
            with (build / f"manuscript-{language}.pdf").open("wb") as stream:
                writer.write(stream)
        return {"status": "built", "validation": {"ok": True}}

    monkeypatch.setattr("aiscience.demo.build_paper", fake_build)
    created = create_demo(tmp_path)
    assert created["status"] == "created"
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "demo fixture"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)

    result = CliRunner().invoke(
        app, ["run", "execute", "demo-robust-location", "robust-location"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["data"]["status"] == "completed"
    assert payload["data"]["ledger_ref"]["object_type"] == "experiment"
    assert all(
        output["storage_policy"] == "git_eligible" for output in payload["data"]["outputs"]
    )
    store = LedgerStore(tmp_path / "projects" / "demo-robust-location")
    assert store.audit().ok
    run_ref = ObjectRef.model_validate(payload["data"]["ledger_ref"])
    typed_run = ExperimentRecord.model_validate(store.read_object(run_ref).payload)
    assert typed_run.log_refs
    assert typed_run.artifact_refs
    assert all(
        not store.source_binding_issues(reference)
        for reference in (*typed_run.log_refs, *typed_run.artifact_refs)
    )
    assert typed_run.reproduction_level is ReproductionLevel.FULL
    assert all(
        subprocess.run(
            [
                "git",
                "check-ignore",
                str(
                    (
                        store.project_dir
                        / str(store.read_object(reference).payload["source_path"])
                    ).relative_to(tmp_path)
                ),
            ],
            cwd=tmp_path,
            check=False,
            capture_output=True,
        ).returncode
        != 0
        for reference in typed_run.log_refs
    )
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "record traceable run"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    clone = tmp_path.parent / f"{tmp_path.name}-clean-clone"
    subprocess.run(
        ["git", "clone", "--quiet", str(tmp_path), str(clone)],
        check=True,
        capture_output=True,
    )
    cloned_store = LedgerStore(clone / "projects" / "demo-robust-location")
    cloned_run = ExperimentRecord.model_validate(cloned_store.read_object(run_ref).payload)
    assert all(
        cloned_store.is_current_reference(reference)
        and not cloned_store.source_binding_issues(reference)
        for reference in (*cloned_run.log_refs, *cloned_run.artifact_refs)
    )
    strict = CliRunner().invoke(
        app, ["validate", "demo-robust-location", "--strict"]
    )
    assert strict.exit_code == 0, strict.output
    stdout_ref = typed_run.log_refs[0]
    stdout_payload = store.read_object(stdout_ref).payload
    stdout_path = store.project_dir / str(stdout_payload["source_path"])
    stdout_path.write_text("tampered\n", encoding="utf-8")
    assert store.source_binding_issues(stdout_ref)
    assert any(
        event.object_ref is not None and event.object_ref.object_type == "experiment"
        for event in store.events()
    )


def test_gate_invalidation_event_revokes_an_earlier_approval(tmp_path: Path) -> None:
    basis = _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    store = LedgerStore(project)
    _approved_gate(store, "study-01", GateKind.G0, basis)
    approved, _, _ = _valid_gate_records(tmp_path, project)
    assert GateKind.G0 in approved

    store.commit_object(
        project_id="study-01",
        object_type="gate.invalidation",
        payload={"gate": "G0", "reason_zh": "受控回退测试"},
        event_type="gate.invalidated",
        event_payload={"gate": "G0"},
    )
    approved, _, invalid = _valid_gate_records(tmp_path, project)
    assert GateKind.G0 not in approved
    assert invalid["G0"] == ["WORKFLOW_ROLLBACK"]


def test_central_g2_approval_binds_the_exact_candidate_manifest(tmp_path: Path) -> None:
    basis = _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    manuscript = project / "paper" / "en" / "manuscript.md"
    manuscript.parent.mkdir(parents=True)
    manuscript.write_text("Safe research candidate.\n", encoding="utf-8")
    prepared = prepare_package(
        tmp_path,
        "study-01",
        allowlist=("paper/en/manuscript.md",),
        reproducibility_level="full",
    )
    assert prepared["status"] == "prepared"
    manifest = project / "delivery" / "candidate" / "manifest.json"
    manifest_ref = record_artifact(
        project,
        "study-01",
        source=manifest,
        object_type="delivery.manifest",
    )
    manager = GateManager(LedgerStore(project))
    packet_ref = manager.request(
        project_id="study-01",
        gate=GateKind.G2,
        basis_commit=basis,
        decisions_zh=("确认当前候选交付包",),
        dependency_roots=(manifest_ref,),
        reproduction_level=ReproductionLevel.FULL,
    )
    manager.record(
        packet_ref=packet_ref,
        decision=GateDecision.APPROVED,
        approver="human-test-reviewer",
        current_basis_commit=basis,
    )

    approval, reasons = _central_g2_approval(tmp_path, project)
    assert reasons == []
    assert approval is not None
    assert approval["validation_source"] == "central_ledger"

    manifest.write_text(manifest.read_text(encoding="utf-8") + " ", encoding="utf-8")
    approval, reasons = _central_g2_approval(tmp_path, project)
    assert approval is None
    assert reasons == ["SOURCE_CONTENT_CHANGED"]


def test_cli_rollback_syncs_and_revokes_current_g2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    basis = _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    store = LedgerStore(project)
    store.write_state(
        ProjectState(project_id="study-01", stage=ProjectStage.REVIEWING).model_dump(
            mode="json"
        )
    )
    (project / "project.yaml").write_text("g1_required: false\n", encoding="utf-8")
    _approved_gate(store, "study-01", GateKind.G2, basis)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["transition", "study-01", "designing", "--rollback"])

    assert result.exit_code == 0, result.output
    state = ProjectState.model_validate(store.read_state())
    assert state.stage is ProjectStage.DESIGNING
    assert state.gates[GateKind.G2].stale
    approved, _, invalid = _valid_gate_records(tmp_path, project)
    assert GateKind.G2 not in approved
    assert invalid["G2"] == ["WORKFLOW_ROLLBACK"]
