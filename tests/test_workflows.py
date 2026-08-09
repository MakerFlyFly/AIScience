# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from filelock import FileLock

from aiscience.delivery import finalize_package, g2_binding, prepare_package
from aiscience.demo import create_demo
from aiscience.gates import GateManager
from aiscience.models import GateDecision, GateKind, ReproductionLevel
from aiscience.paper import build_paper, validate_paper
from aiscience.runner import execute_run
from aiscience.scaffold import record_artifact
from aiscience.storage import LedgerStore


def _git_repo(path: Path) -> str:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=path, check=True)
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=path, check=True)
    (path / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=path, check=True, capture_output=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


def _commit_all(path: Path, message: str = "fixture") -> str:
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", message], cwd=path, check=True, capture_output=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


def _install_project_template(repo: Path) -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / ".agents"
        / "skills"
        / "research-orchestrator"
        / "assets"
        / "project-template"
    )
    target = repo / ".agents" / "skills" / "research-orchestrator" / "assets" / "project-template"
    target.parent.mkdir(parents=True)
    shutil.copytree(source, target)


def _demo_runner_plan(
    repo: Path,
    *,
    project_id: str = "demo-runner",
    plan_id: str = "plan",
    script_text: str = "print('ok')\n",
    inputs: list[dict[str, str]] | None = None,
    expected_outputs: list[str | dict[str, object]] | None = None,
) -> tuple[Path, dict[str, object]]:
    gitignore = repo / ".gitignore"
    existing_ignore = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    if ".aiscience-data/" not in existing_ignore:
        gitignore.write_text(existing_ignore + ".aiscience-data/\n", encoding="utf-8")
    project = repo / "projects" / project_id
    (project / "experiments" / "plans").mkdir(parents=True)
    (project / "gates").mkdir(parents=True)
    (project / "design").mkdir(parents=True)
    script = project / "experiment.py"
    script.write_text(script_text, encoding="utf-8")
    protocol = project / "design" / "protocol.md"
    protocol.write_text("# frozen demo protocol\n", encoding="utf-8")
    (project / "gates" / "DEMO-G2.json").write_text(
        json.dumps({"status": "demo_only_not_human_approval"}), encoding="utf-8"
    )
    plan: dict[str, object] = {
        "plan_id": plan_id,
        "execution_mode": "demo_fixture",
        "demo_only": True,
        "argv": [sys.executable, "experiment.py", "--token=supersecretvalue"],
        "cwd": ".",
        "timeout_seconds": 10,
        "expected_outputs": expected_outputs or [],
        "inputs": inputs or [],
        "protocol": {
            "path": "design/protocol.md",
            "sha256": hashlib.sha256(protocol.read_bytes()).hexdigest(),
        },
        "scripts": [
            {
                "path": "experiment.py",
                "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
            }
        ],
        "seeds": {"python": 7},
    }
    (project / "experiments" / "plans" / f"{plan_id}.json").write_text(
        json.dumps(plan), encoding="utf-8"
    )
    return project, plan


def test_execute_run_is_traceable_and_shell_free(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    project, _ = _demo_runner_plan(
        tmp_path,
        script_text=(
            "from pathlib import Path\n"
            "print('password=supersecretvalue')\n"
            "Path('result.txt').write_text('ok', encoding='utf-8')\n"
        ),
        expected_outputs=["result.txt"],
    )
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    basis = _commit_all(tmp_path)
    result = execute_run(tmp_path, "demo-runner", "plan")
    assert result["status"] == "completed"
    assert result["basis_commit"] == basis
    assert result["shell"] is False
    assert result["outputs"][0]["sha256"] == hashlib.sha256(b"ok").hexdigest()
    archived = project / "runs" / result["run_id"] / result["outputs"][0]["archived_path"]
    assert archived.read_bytes() == b"ok"
    assert result["enforcement"]["network"] == "observed_only"
    assert result["environment"]["uv_lock_sha256"] == hashlib.sha256(
        (tmp_path / "uv.lock").read_bytes()
    ).hexdigest()
    assert result["logs"]["stdout"]["redactions"] == ["GENERIC_SECRET"]
    assert result["argv"][-1] == "--[REDACTED:GENERIC_SECRET]"
    assert result["argv_redactions"] == ["GENERIC_SECRET"]
    stdout = project / "runs" / result["run_id"] / result["logs"]["stdout"]["path"]
    assert "supersecretvalue" not in stdout.read_text(encoding="utf-8")
    assert (project / "runs" / result["run_id"] / "run.json").is_file()


def test_execute_run_distinguishes_missing_input(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    _demo_runner_plan(
        tmp_path,
        plan_id="missing",
        inputs=[{"path": "data/missing.csv", "sha256": "0" * 64}],
    )
    _commit_all(tmp_path)
    result = execute_run(tmp_path, "demo-runner", "missing")
    assert result["status"] == "input_unavailable"
    assert result["failure_kind"] is None


def test_execute_run_rejects_project_concurrency(
    tmp_path: Path,
) -> None:
    _git_repo(tmp_path)
    project, _ = _demo_runner_plan(tmp_path)
    _commit_all(tmp_path)
    lock_path = project / ".aiscience-data" / "run.lock"
    lock_path.parent.mkdir(parents=True)
    with FileLock(lock_path):
        result = execute_run(tmp_path, "demo-runner", "plan")
    assert result["failure_kind"] == "concurrent_run"


def test_execute_run_rejects_plan_path_traversal(tmp_path: Path) -> None:
    result = execute_run(tmp_path, "p1", "../../outside")
    assert result["failure_kind"] == "invalid_plan_id"


def test_timeout_terminates_spawned_child_process(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    project, plan = _demo_runner_plan(
        tmp_path,
        script_text=(
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', "
            '"import time; from pathlib import Path; time.sleep(1); "'
            '"Path(\'escaped.txt\').write_text(\'escaped\', encoding=\'utf-8\')"])\n'
            "time.sleep(5)\n"
        ),
    )
    plan["timeout_seconds"] = 0.2
    (project / "experiments" / "plans" / "plan.json").write_text(
        json.dumps(plan), encoding="utf-8"
    )
    _commit_all(tmp_path)

    result = execute_run(tmp_path, "demo-runner", "plan")
    time.sleep(1.3)

    assert result["status"] == "failed"
    assert result["failure_kind"] == "timeout"
    assert not (project / "escaped.txt").exists()


def test_demo_fast_validation_and_stale_detection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _git_repo(tmp_path)
    _install_project_template(tmp_path)
    monkeypatch.setattr(
        "aiscience.demo.build_paper",
        lambda *_args, **_kwargs: {"status": "built", "validation": {"ok": True}},
    )
    result = create_demo(tmp_path)
    assert result["status"] == "created"
    assert result["network_used"] is False
    assert result["delivery"]["status"] == "prepared"
    assert result["state"]["stage"] == "delivery_ready"
    assert result["state"]["status"] == "partial"
    assert result["state"]["gates"] == {}
    assert result["ledger_audit"]["ok"] is True
    assert LedgerStore(tmp_path / "projects" / "demo-robust-location").audit().ok is True
    validation = validate_paper(tmp_path, "demo-robust-location")
    assert validation["ok"] is True
    citation_map_path = (
        tmp_path / "projects" / "demo-robust-location" / "paper" / "citation-map.json"
    )
    citation_map = json.loads(citation_map_path.read_text(encoding="utf-8"))
    english_hash = citation_map.pop("english_manuscript_sha256")
    citation_map.pop("chinese_source_english_sha256")
    citation_map["canonical_manuscript_sha256"] = english_hash
    chinese = tmp_path / "projects" / "demo-robust-location" / "paper" / "zh" / "manuscript.md"
    citation_map["reader_manuscript_sha256"] = hashlib.sha256(chinese.read_bytes()).hexdigest()
    citation_map["reader_status"] = "current"
    citation_map_path.write_text(json.dumps(citation_map), encoding="utf-8")
    assert validate_paper(tmp_path, "demo-robust-location")["ok"] is True
    original_chinese = chinese.read_text(encoding="utf-8")
    chinese.write_text(original_chinese + "\n篡改。\n", encoding="utf-8")
    assert "CHINESE_STALE" in {
        item["code"] for item in validate_paper(tmp_path, "demo-robust-location")["findings"]
    }
    chinese.write_text(original_chinese, encoding="utf-8")
    citation_map["chinese_source_english_sha256"] = english_hash
    citation_map_path.write_text(json.dumps(citation_map), encoding="utf-8")
    manuscript = tmp_path / "projects" / "demo-robust-location" / "paper" / "en" / "manuscript.md"
    manuscript.write_text(manuscript.read_text(encoding="utf-8") + "\nChanged.\n", encoding="utf-8")
    stale = validate_paper(tmp_path, "demo-robust-location")
    assert stale["ok"] is False
    assert stale["stale"] is True
    assert {item["code"] for item in stale["findings"]} >= {"CITATION_MAP_STALE", "CHINESE_STALE"}


def test_demo_overwrite_rejects_formal_namespace_before_deletion(tmp_path: Path) -> None:
    formal = tmp_path / "projects" / "formal-study"
    formal.mkdir(parents=True)
    sentinel = formal / "sentinel.txt"
    sentinel.write_text("must survive\n", encoding="utf-8")

    with pytest.raises(ValueError, match="demo-"):
        create_demo(tmp_path, "formal-study", overwrite=True)

    assert sentinel.read_text(encoding="utf-8") == "must survive\n"


def test_build_reports_missing_tool_without_failing_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    _install_project_template(tmp_path)
    monkeypatch.setattr(
        "aiscience.demo.build_paper",
        lambda *_args, **_kwargs: {"status": "built", "validation": {"ok": True}},
    )
    create_demo(tmp_path)
    monkeypatch.setattr("aiscience.paper.shutil.which", lambda _name: None)
    result = build_paper(tmp_path, "demo-robust-location")
    assert result["status"] == "tool_unavailable"
    assert result["validation"]["ok"] is True


def test_build_rejects_missing_glyph_or_resource_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    _install_project_template(tmp_path)
    monkeypatch.setattr(
        "aiscience.demo.build_paper",
        lambda *_args, **_kwargs: {"status": "built", "validation": {"ok": True}},
    )
    create_demo(tmp_path)
    monkeypatch.setattr("aiscience.paper.shutil.which", lambda name: name)

    def fake_pandoc(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        output = Path(command[command.index("--output") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(b"%PDF-1.4\n% test fixture\n")
        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "[WARNING] Missing character: simulated visual corruption",
        )

    monkeypatch.setattr("aiscience.paper.subprocess.run", fake_pandoc)
    result = build_paper(tmp_path, "demo-robust-location")
    assert result["status"] == "failed"
    assert all(output["fatal_warning"] for output in result["outputs"].values())


def test_delivery_rejects_incomplete_bundle_even_with_manifest_bound_g2(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "p1"
    (project / "paper" / "en").mkdir(parents=True)
    (project / "paper" / "en" / "manuscript.md").write_text("Safe paper.\n", encoding="utf-8")
    basis = _commit_all(tmp_path)
    prepared = prepare_package(tmp_path, "p1", allowlist=("paper/en/manuscript.md",))
    assert prepared["status"] == "prepared"
    blocked = finalize_package(tmp_path, "p1", create_tag=False)
    assert blocked["reason"] == "g2_missing"
    binding = g2_binding(tmp_path, "p1")
    manifest_ref = record_artifact(
        project,
        "p1",
        source=project / "delivery" / "candidate" / "manifest.json",
        object_type="delivery.manifest",
    )
    approval_basis = _commit_all(tmp_path, "freeze candidate")
    manager = GateManager(LedgerStore(project))
    packet_ref = manager.request(
        project_id="p1",
        gate=GateKind.G2,
        basis_commit=approval_basis,
        decisions_zh=("确认候选交付包",),
        dependency_roots=(manifest_ref,),
        reproduction_level=ReproductionLevel.FULL,
    )
    record_ref = manager.record(
        packet_ref=packet_ref,
        decision=GateDecision.APPROVED,
        approver="Human Tester",
        current_basis_commit=approval_basis,
    )
    _commit_all(tmp_path, "record G2")
    approval = {
        "gate_record_ref": record_ref.model_dump(mode="json"),
        "candidate_manifest_sha256": binding["candidate_manifest_sha256"],
    }
    final = finalize_package(tmp_path, "p1", approval=approval, create_tag=False)
    assert final["status"] == "blocked"
    assert str(final["reason"]).startswith("g2_readiness_failed:")
    assert "G2_REQUIRED_FILE_MISSING" in str(final["reason"])
    assert basis != approval_basis


def test_delivery_blocks_secrets_and_absolute_paths(tmp_path: Path) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "p"
    project.mkdir(parents=True)
    (project / "README.md").write_text(
        '{"password":"correcthorsebatterystaple"}\n'
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "Local C:\\Users\\researcher\\data.csv\n",
        encoding="utf-8",
    )
    result = prepare_package(tmp_path, "p", allowlist=("README.md",))
    assert result["status"] == "blocked"
    codes = {item["code"] for item in result["findings"]}
    assert {"GENERIC_SECRET", "PRIVATE_KEY", "ABSOLUTE_PATH"} <= codes
