from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from aiscience.gates import GateManager
from aiscience.local_cas import LocalCASIntegrityError, validate_local_cas_manifest
from aiscience.models import ExperimentRecord, GateDecision, GateKind, ProjectStage, RunStatus
from aiscience.run_ledger import record_experiment_run
from aiscience.runner import execute_run
from aiscience.scaffold import record_artifact
from aiscience.state import ProjectState
from aiscience.storage import LedgerStore


def _commit(repo: Path, message: str) -> str:
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", message], cwd=repo, check=True, capture_output=True
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _init_git(repo: Path) -> str:
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True
    )
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=repo, check=True)
    (repo / ".gitignore").write_text(".aiscience-data/\n", encoding="utf-8")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    return _commit(repo, "seed")


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _formal_fixture(
    repo: Path,
    *,
    include_g0: bool = True,
    include_g1: bool = False,
    network: bool = False,
    mutate_config: Any = None,
) -> Path:
    first_basis = _init_git(repo)
    project = repo / "projects" / "formal-runner"
    (project / "experiments" / "plans").mkdir(parents=True)
    (project / "design").mkdir(parents=True)
    protocol = project / "design" / "protocol.md"
    protocol.write_text("# Frozen protocol\n", encoding="utf-8")
    script = project / "experiment.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('result.txt').write_text('result', encoding='utf-8')\n",
        encoding="utf-8",
    )
    config: dict[str, Any] = {
        "schema_version": "1.0",
        "project_id": "formal-runner",
        "defaults": {
            "paid_budget": 0,
            "gpu_authorized": False,
            "experiment_concurrency": 1,
            "network_after_g0": True,
        },
        "g1_required": False,
        "research_contract": {
            "success_criteria": ["produce result"],
            "scope_in": ["fixture"],
            "scope_out": [],
            "confidentiality": "public synthetic data",
            "data_license_ethics": "synthetic; no restrictions",
            "deliverables": ["result.txt"],
            "public_query_boundary": "no public queries",
        },
        "limits": {
            "time_hours": 1,
            "max_runs": 2,
            "disk_mib": 64,
            "data_scope": ["synthetic"],
        },
    }
    if mutate_config is not None:
        mutate_config(config)
    (project / "project.yaml").write_text(
        yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    store = LedgerStore(project)
    store.write_state(ProjectState(project_id="formal-runner", stage=ProjectStage.EXPERIMENTING))
    protocol_ref = store.commit_object(
        project_id="formal-runner",
        object_type="research.protocol",
        payload={
            "source_path": "design/protocol.md",
            "source_sha256": _hash(protocol),
            "sha256": _hash(protocol),
            "frozen": True,
        },
        event_type="research.protocol_locked",
    )
    contract_ref = record_artifact(
        project,
        "formal-runner",
        source=project / "project.yaml",
        object_type="project.charter",
    )
    approval_basis = _commit(repo, "contract and protocol")
    manager = GateManager(store)
    if include_g0:
        packet = manager.request(
            project_id="formal-runner",
            gate=GateKind.G0,
            basis_commit=approval_basis,
            decisions_zh=("批准研究合同",),
            dependency_roots=(contract_ref,),
        )
        manager.record(
            packet_ref=packet,
            decision=GateDecision.APPROVED,
            approver="Human Tester",
            current_basis_commit=approval_basis,
        )
    plan = {
        "schema_version": "1.0",
        "plan_id": "formal",
        "execution_mode": "formal",
        "argv": [sys.executable, "experiment.py"],
        "cwd": ".",
        "timeout_seconds": 10,
        "protocol": {"path": "design/protocol.md", "sha256": _hash(protocol)},
        "scripts": [{"path": "experiment.py", "sha256": _hash(script)}],
        "inputs": [],
        "expected_outputs": [
            {"path": "result.txt", "sensitive": False, "redistributable": True}
        ],
        "budget": {
            "estimated_time_hours": 0.01,
            "estimated_runs": 1,
            "estimated_disk_mib": 1,
            "estimated_paid_cost": 0,
            "data_scope": ["synthetic"],
        },
        "requirements": {
            "network": network,
            "gpu": False,
            "sensitive_data": False,
            "external_action": False,
            "irreversible": False,
            "high_risk": False,
            "isolation": {
                "process_tree": "best_effort",
                "network": "observed_only",
                "filesystem": "observed_only",
                "gpu": "observed_only",
                "memory": "observed_only",
            },
        },
        "seeds": {"python": 1},
    }
    (project / "experiments" / "plans" / "formal.json").write_text(
        json.dumps(plan), encoding="utf-8"
    )
    if include_g1:
        plan_ref = record_artifact(
            project,
            "formal-runner",
            source=project / "experiments" / "plans" / "formal.json",
            object_type="experiment.plan",
        )
        plan_basis = _commit(repo, "proposed executable plan")
        packet = manager.request(
            project_id="formal-runner",
            gate=GateKind.G1,
            basis_commit=plan_basis,
            decisions_zh=("批准条件执行",),
            dependency_roots=(protocol_ref, plan_ref),
        )
        manager.record(
            packet_ref=packet,
            decision=GateDecision.APPROVED,
            approver="Human Tester",
            current_basis_commit=plan_basis,
        )
    _commit(repo, "approved executable plan")
    assert first_basis != approval_basis
    return project


def _demo_fixture(
    repo: Path, script_text: str, declaration: str | dict[str, object]
) -> Path:
    _init_git(repo)
    project = repo / "projects" / "demo-cas"
    (project / "experiments" / "plans").mkdir(parents=True)
    (project / "design").mkdir(parents=True)
    (project / "gates").mkdir(parents=True)
    protocol = project / "design" / "protocol.md"
    protocol.write_text("demo protocol\n", encoding="utf-8")
    script = project / "experiment.py"
    script.write_text(script_text, encoding="utf-8")
    (project / "gates" / "DEMO-G2.json").write_text(
        json.dumps({"status": "demo_only_not_human_approval"}), encoding="utf-8"
    )
    plan = {
        "execution_mode": "demo_fixture",
        "demo_only": True,
        "argv": [sys.executable, "experiment.py"],
        "cwd": ".",
        "timeout_seconds": 20,
        "protocol": {"path": "design/protocol.md", "sha256": _hash(protocol)},
        "scripts": [{"path": "experiment.py", "sha256": _hash(script)}],
        "inputs": [],
        "expected_outputs": [declaration],
    }
    (project / "experiments" / "plans" / "cas.json").write_text(
        json.dumps(plan), encoding="utf-8"
    )
    _commit(repo, "demo CAS fixture")
    return project


def test_formal_plan_uses_real_clean_head_without_self_reference(tmp_path: Path) -> None:
    project = _formal_fixture(tmp_path)
    expected_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    plan = json.loads(
        (project / "experiments" / "plans" / "formal.json").read_text(encoding="utf-8")
    )
    assert "basis_commit" not in plan
    result = execute_run(tmp_path, "formal-runner", "formal")
    assert result["status"] == "completed"
    assert result["basis_commit"] == expected_head
    assert result["authorization"]["valid_gates"] == ["G0"]


def test_formal_run_requires_g0(tmp_path: Path) -> None:
    _formal_fixture(tmp_path, include_g0=False)
    result = execute_run(tmp_path, "formal-runner", "formal")
    assert result["error_code"] == "G0_REQUIRED"


def test_network_or_isolation_gap_requires_g1(tmp_path: Path) -> None:
    _formal_fixture(tmp_path, network=True)
    result = execute_run(tmp_path, "formal-runner", "formal")
    assert result["error_code"] == "G1_REQUIRED"
    assert "network" in result["triggers"]


def test_network_can_run_after_explicit_g1(tmp_path: Path) -> None:
    _formal_fixture(tmp_path, network=True, include_g1=True)
    result = execute_run(tmp_path, "formal-runner", "formal")
    assert result["status"] == "completed"
    assert result["authorization"]["valid_gates"] == ["G0", "G1"]


def test_gate_closure_must_bind_the_exact_contract_and_plan(tmp_path: Path) -> None:
    project = _formal_fixture(tmp_path, network=True)
    store = LedgerStore(project)
    protocol_ref = next(
        event.object_ref
        for event in reversed(store.events())
        if event.object_ref is not None and event.object_ref.object_type == "research.protocol"
    )
    basis = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    manager = GateManager(store)
    packet = manager.request(
        project_id="formal-runner",
        gate=GateKind.G1,
        basis_commit=basis,
        decisions_zh=("错误地只批准协议",),
        dependency_roots=(protocol_ref,),
    )
    manager.record(
        packet_ref=packet,
        decision=GateDecision.APPROVED,
        approver="Human Tester",
        current_basis_commit=basis,
    )
    _commit(tmp_path, "unrelated G1 approval")

    result = execute_run(tmp_path, "formal-runner", "formal")

    assert result["error_code"] == "G1_REQUIRED"


def test_g0_closure_must_bind_project_yaml(tmp_path: Path) -> None:
    project = _formal_fixture(tmp_path)
    store = LedgerStore(project)
    protocol_ref = next(
        event.object_ref
        for event in reversed(store.events())
        if event.object_ref is not None and event.object_ref.object_type == "research.protocol"
    )
    basis = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    manager = GateManager(store)
    packet = manager.request(
        project_id="formal-runner",
        gate=GateKind.G0,
        basis_commit=basis,
        decisions_zh=("错误地批准无关制品",),
        dependency_roots=(protocol_ref,),
    )
    manager.record(
        packet_ref=packet,
        decision=GateDecision.APPROVED,
        approver="Human Tester",
        current_basis_commit=basis,
    )
    _commit(tmp_path, "unrelated G0 approval")

    result = execute_run(tmp_path, "formal-runner", "formal")

    assert result["error_code"] == "G0_REQUIRED"


@pytest.mark.parametrize("include_g1", [False, True])
def test_over_budget_plan_requires_and_can_use_plan_bound_g1(
    tmp_path: Path, include_g1: bool
) -> None:
    def lower_time_limit(config: dict[str, Any]) -> None:
        config["limits"]["time_hours"] = 0.005

    _formal_fixture(tmp_path, include_g1=include_g1, mutate_config=lower_time_limit)

    result = execute_run(tmp_path, "formal-runner", "formal")

    if include_g1:
        assert result["status"] == "completed"
        assert "budget_exception:time_hours" in result["authorization"]["g1_triggers"]
    else:
        assert result["error_code"] == "G1_REQUIRED"
        assert "budget_exception:time_hours" in result["triggers"]


def test_missing_contract_limit_fails_closed(tmp_path: Path) -> None:
    def remove_limit(config: dict[str, Any]) -> None:
        config["limits"].pop("max_runs")

    _formal_fixture(tmp_path, mutate_config=remove_limit)
    result = execute_run(tmp_path, "formal-runner", "formal")
    assert result["error_code"] == "PROJECT_LIMIT_MISSING"


def test_plan_must_be_the_committed_head_version(tmp_path: Path) -> None:
    project = _formal_fixture(tmp_path)
    plan = project / "experiments" / "plans" / "formal.json"
    plan.write_text(plan.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    result = execute_run(tmp_path, "formal-runner", "formal")
    assert result["error_code"] == "GIT_WORKTREE_DIRTY"


def test_clean_head_rejects_git_normalized_crlf_plan(tmp_path: Path) -> None:
    _formal_fixture(tmp_path)
    plan_path = tmp_path / "projects" / "formal-runner" / "experiments" / "plans" / "formal.json"
    committed = json.dumps(
        json.loads(plan_path.read_text(encoding="utf-8")), indent=2, sort_keys=True
    ) + "\n"
    (tmp_path / ".gitattributes").write_text(
        "projects/formal-runner/experiments/plans/formal.json text eol=lf\n",
        encoding="utf-8",
        newline="\n",
    )
    subprocess.run(["git", "config", "core.autocrlf", "true"], cwd=tmp_path, check=True)
    plan_path.write_text(committed, encoding="utf-8", newline="\n")
    _commit(tmp_path, "canonical LF plan")
    plan_path.write_bytes(committed.replace("\n", "\r\n").encode("utf-8"))
    subprocess.run(["git", "add", "--", plan_path], cwd=tmp_path, check=True)

    result = execute_run(tmp_path, "formal-runner", "formal")

    assert result["status"] == "failed"
    assert result["error_code"] == "GIT_NORMALIZATION_MISMATCH"


def test_clean_filter_equivalent_crlf_script_is_rejected(tmp_path: Path) -> None:
    project = _formal_fixture(tmp_path)
    script = project / "experiment.py"
    plan_path = project / "experiments" / "plans" / "formal.json"
    (tmp_path / ".gitattributes").write_text(
        "projects/formal-runner/experiment.py text eol=lf\n",
        encoding="utf-8",
        newline="\n",
    )
    script_text = script.read_text(encoding="utf-8").replace("\r\n", "\n")
    script.write_bytes(script_text.replace("\n", "\r\n").encode("utf-8"))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["scripts"][0]["sha256"] = _hash(script)
    plan_path.write_text(json.dumps(plan), encoding="utf-8", newline="\n")
    subprocess.run(["git", "config", "core.autocrlf", "true"], cwd=tmp_path, check=True)
    _commit(tmp_path, "clean-filter-equivalent CRLF script")
    assert subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout == ""

    result = execute_run(tmp_path, "formal-runner", "formal")

    assert result["status"] == "failed"
    assert result["error_code"] == "GIT_NORMALIZATION_MISMATCH"
    assert result["path"].endswith("experiment.py")


@pytest.mark.parametrize("legacy", ["deadbeef", "0" * 40])
def test_plan_embedded_basis_commit_is_rejected(tmp_path: Path, legacy: str) -> None:
    project = _formal_fixture(tmp_path)
    plan_path = project / "experiments" / "plans" / "formal.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["basis_commit"] = legacy
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    _commit(tmp_path, "legacy self reference")
    result = execute_run(tmp_path, "formal-runner", "formal")
    assert result["error_code"] == "PLAN_BASIS_SELF_REFERENCE_FORBIDDEN"


def test_large_output_is_moved_to_gitignored_local_cas(tmp_path: Path) -> None:
    project = _demo_fixture(
        tmp_path,
        "from pathlib import Path\n"
        "Path('large.bin').write_bytes(b'x' * (10 * 1024 * 1024 + 1))\n",
        {"path": "large.bin", "sensitive": False, "redistributable": True},
    )
    result = execute_run(tmp_path, "demo-cas", "cas")
    output = result["outputs"][0]
    assert result["status"] == "completed"
    assert output["storage_policy"] == "local_cas"
    assert result["reproducibility"] == "local_only"
    assert not (project / "large.bin").exists()
    manifest = project / "runs" / result["run_id"] / output["cas_manifest_path"]
    assert manifest.is_file()
    validate_local_cas_manifest(project, manifest)
    algorithm, digest = output["cas_address"].split(":", 1)
    blob = project / ".aiscience-data" / "cas" / algorithm / digest[:2] / digest
    assert blob.is_file()
    blob.write_bytes(b"tampered")
    with pytest.raises(LocalCASIntegrityError) as exc_info:
        validate_local_cas_manifest(project, manifest)
    assert exc_info.value.code in {"CAS_BLOB_SIZE_MISMATCH", "CAS_BLOB_HASH_MISMATCH"}
    blob.unlink()
    with pytest.raises(LocalCASIntegrityError) as exc_info:
        validate_local_cas_manifest(project, manifest)
    assert exc_info.value.code == "CAS_BLOB_MISSING"


@pytest.mark.parametrize(
    ("filename", "script"),
    [
        (
            "numbers.csv",
            "from pathlib import Path\n"
            "Path('numbers.csv').write_text('value\\n0.123456789012345678\\n', encoding='utf-8')\n",
        ),
        (
            "numbers.json",
            "from pathlib import Path\n"
            "payload = '{\"value\": 0.123456789012345678}'\n"
            "Path('numbers.json').write_text(payload, encoding='utf-8')\n",
        ),
    ],
)
def test_scientific_decimals_are_not_misclassified_as_sensitive(
    tmp_path: Path, filename: str, script: str
) -> None:
    project = _demo_fixture(tmp_path, script, filename)

    result = execute_run(tmp_path, "demo-cas", "cas")

    output = result["outputs"][0]
    assert result["status"] == "completed"
    assert result["reproducibility"] == "full"
    assert output["storage_policy"] == "git_eligible"
    assert output["scan_findings"] == []
    assert (project / filename).is_file()


def test_sensitive_output_uses_keyed_address_and_no_plain_sha(tmp_path: Path) -> None:
    project = _demo_fixture(
        tmp_path,
        "from pathlib import Path\n"
        "Path('private.txt').write_text('email=user@example.com', encoding='utf-8')\n",
        "private.txt",
    )
    result = execute_run(tmp_path, "demo-cas", "cas")
    output = result["outputs"][0]
    assert result["status"] == "completed"
    assert output["storage_policy"] == "local_cas"
    assert output["sha256"] is None
    assert output["cas_address"].startswith("hmac-sha256:")
    assert not (project / "private.txt").exists()
    run_json = project / "runs" / result["run_id"] / "run.json"
    assert "user@example.com" not in run_json.read_text(encoding="utf-8")
    manifest = project / "runs" / result["run_id"] / output["cas_manifest_path"]
    validate_local_cas_manifest(project, manifest)
    algorithm, digest = output["cas_address"].split(":", 1)
    blob = project / ".aiscience-data" / "cas" / algorithm / digest[:2] / digest
    original_blob = blob.read_bytes()
    blob.write_bytes(b"x" * len(original_blob))
    with pytest.raises(LocalCASIntegrityError) as exc_info:
        validate_local_cas_manifest(project, manifest)
    assert exc_info.value.code == "CAS_BLOB_HASH_MISMATCH"
    blob.write_bytes(original_blob)
    key = project / ".aiscience-data" / "cas.key"
    key.unlink()
    with pytest.raises(LocalCASIntegrityError) as exc_info:
        validate_local_cas_manifest(project, manifest)
    assert exc_info.value.code == "CAS_KEY_MISSING"
    assert not key.exists()


def test_nonredistributable_output_is_local_only(tmp_path: Path) -> None:
    project = _demo_fixture(
        tmp_path,
        "from pathlib import Path\n"
        "Path('licensed.dat').write_bytes(b'licensed fixture')\n",
        {"path": "licensed.dat", "sensitive": False, "redistributable": False},
    )
    result = execute_run(tmp_path, "demo-cas", "cas")
    output = result["outputs"][0]
    assert output["storage_policy"] == "local_cas"
    assert output["redistributable"] is False
    assert not (project / "licensed.dat").exists()


def test_failed_run_can_be_retried_with_typed_lineage(tmp_path: Path) -> None:
    project = _formal_fixture(tmp_path)
    script = project / "experiment.py"
    plan_path = project / "experiments" / "plans" / "formal.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    script.write_text("raise SystemExit(2)\n", encoding="utf-8")
    plan["scripts"][0]["sha256"] = _hash(script)
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    _commit(tmp_path, "failing attempt")
    failed = execute_run(tmp_path, "formal-runner", "formal")
    assert failed["status"] == "failed"
    failed_ref = record_experiment_run(project, project.name, plan_path, failed)
    failed_record = ExperimentRecord.model_validate(
        LedgerStore(project).read_object(failed_ref).payload
    )
    assert failed_record.status is RunStatus.FAILED
    _commit(tmp_path, "record failed attempt")

    script.write_text(
        "from pathlib import Path\n"
        "Path('result.txt').write_text('result', encoding='utf-8')\n",
        encoding="utf-8",
    )
    plan["scripts"][0]["sha256"] = _hash(script)
    plan["retry_of"] = failed["run_id"]
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    _commit(tmp_path, "retry plan")
    retried = execute_run(tmp_path, "formal-runner", "formal")
    assert retried["status"] == "completed"
    retry_ref = record_experiment_run(project, project.name, plan_path, retried)
    store = LedgerStore(project)
    retry_object = store.read_object(retry_ref)
    retry_record = ExperimentRecord.model_validate(retry_object.payload)
    assert retry_record.retry_of == failed_ref
    assert failed_ref in retry_object.dependencies

    invalid = dict(retried)
    invalid["run_id"] = "run_1234567890abcdef"
    invalid["retry_of"] = retried["run_id"]
    invalid_root = project / "runs" / str(invalid["run_id"])
    invalid_root.mkdir()
    (invalid_root / "run.json").write_text(json.dumps(invalid), encoding="utf-8")
    with pytest.raises(ValueError, match="failed 或 partial"):
        record_experiment_run(project, project.name, plan_path, invalid)


def test_retry_rejects_missing_or_cross_project_predecessor(tmp_path: Path) -> None:
    project = _formal_fixture(tmp_path)
    plan_path = project / "experiments" / "plans" / "formal.json"
    result = execute_run(tmp_path, "formal-runner", "formal")
    assert result["status"] == "completed"
    result["retry_of"] = "run_from_another_project_001"
    with pytest.raises(ValueError, match="不存在于当前项目"):
        record_experiment_run(project, project.name, plan_path, result)
