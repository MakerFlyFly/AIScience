from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aiscience.cli import _run_failure_exit_code, app
from aiscience.envelope import ExitCode
from aiscience.models import ProjectStage
from aiscience.state import ProjectState
from aiscience.storage import LedgerStore


def _git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"],
        cwd=path,
        check=True,
    )
    (path / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "add", "seed.txt"], cwd=path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "seed"], cwd=path, check=True, capture_output=True
    )


def test_typer_parse_error_uses_json_envelope() -> None:
    result = CliRunner().invoke(app, ["project", "init"])

    assert result.exit_code == int(ExitCode.INPUT)
    payload = json.loads(result.output)
    assert payload == {
        "ok": False,
        "command": "project init",
        "project_id": None,
        "data": {},
        "errors": [
            {
                "code": "CLI_USAGE_ERROR",
                "message_zh": "命令参数无效：Missing argument 'project_id'.",
                "details": {},
            }
        ],
        "warnings": [],
    }


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"status": "failed", "failure_kind": "invalid_plan"}, ExitCode.INPUT),
        ({"status": "failed", "failure_kind": "unsafe_environment"}, ExitCode.INPUT),
        ({"status": "failed", "failure_kind": "concurrent_run"}, ExitCode.INTEGRITY),
        ({"status": "input_unavailable"}, ExitCode.UNAVAILABLE),
        ({"status": "failed", "failure_kind": "launch"}, ExitCode.UNAVAILABLE),
        (
            {
                "status": "failed",
                "failure_kind": "precondition",
                "error_code": "PROJECT_STATE_INVALID",
            },
            ExitCode.INTEGRITY,
        ),
        (
            {
                "status": "failed",
                "failure_kind": "precondition",
                "error_code": "PLAN_TIMEOUT_INVALID",
            },
            ExitCode.INPUT,
        ),
        (
            {
                "status": "failed",
                "failure_kind": "precondition",
                "error_code": "G0_REQUIRED",
            },
            ExitCode.PRECONDITION,
        ),
    ],
)
def test_runner_failures_map_to_stable_exit_classes(
    result: dict[str, object], expected: ExitCode
) -> None:
    assert _run_failure_exit_code(result) is expected


@pytest.mark.parametrize("command", ["status", "validate"])
def test_status_and_validate_reject_schema_valid_state_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    store = LedgerStore(project)
    store.write_state(ProjectState(project_id="study-01").model_dump(mode="json"))
    tampered = store.read_state()
    assert isinstance(tampered, dict)
    tampered["stage"] = ProjectStage.REVIEWING.value
    store.state_path.write_text(json.dumps(tampered), encoding="utf-8")
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)

    args = [command, "study-01", "--strict"] if command == "validate" else [command, "study-01"]
    result = CliRunner().invoke(app, args)

    assert result.exit_code == int(ExitCode.INTEGRITY)
    assert json.loads(result.output)["errors"][0]["code"] == "STATE_PROJECTION_INVALID"


def test_repo_scan_blocks_a_staged_project_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    project.mkdir(parents=True)
    note = project / "notes.md"
    note.write_text("api_key=" + "unsafevalue12345" + "\n", encoding="utf-8")
    subprocess.run(["git", "add", note], cwd=tmp_path, check=True)
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)

    result = CliRunner().invoke(app, ["repo-scan"])

    assert result.exit_code == int(ExitCode.INTEGRITY)
    payload = json.loads(result.output)
    assert payload["errors"][0]["code"] == "GIT_SECRET_OR_PII"
    assert payload["errors"][0]["details"]["source"] in {"index", "working_tree"}


def test_delivered_cannot_be_written_by_generic_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    store = LedgerStore(project)
    store.write_state(
        ProjectState(
            project_id="study-01",
            stage=ProjectStage.DELIVERY_READY,
        ).model_dump(mode="json")
    )
    (project / "project.yaml").write_text("g1_required: false\n", encoding="utf-8")
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)

    result = CliRunner().invoke(app, ["transition", "study-01", "delivered"])

    assert result.exit_code == int(ExitCode.PRECONDITION)
    assert json.loads(result.output)["errors"][0]["code"] == "DELIVERED_REQUIRES_FINALIZE"


def test_package_finalize_requires_delivery_ready_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    LedgerStore(project).write_state(ProjectState(project_id="study-01").model_dump(mode="json"))
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)

    result = CliRunner().invoke(app, ["package", "finalize", "study-01"])

    assert result.exit_code == int(ExitCode.PRECONDITION)
    assert json.loads(result.output)["errors"][0]["code"] == "DELIVERY_READY_REQUIRED"


def test_package_finalize_has_no_no_tag_escape() -> None:
    result = CliRunner().invoke(
        app,
        ["package", "finalize", "study-01", "--no-create-tag"],
    )

    assert result.exit_code == int(ExitCode.INPUT)
    assert json.loads(result.output)["errors"][0]["code"] == "CLI_USAGE_ERROR"


def test_package_finalize_commits_delivered_fact_then_creates_annotated_tag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    store = LedgerStore(project)
    store.write_state(
        ProjectState(
            project_id="study-01",
            stage=ProjectStage.DELIVERY_READY,
        ).model_dump(mode="json")
    )
    manifest = project / "delivery" / "candidate" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"package_id": "pkg_1234567890abcdef"}), encoding="utf-8"
    )
    gate_ref = store.commit_object(
        project_id="study-01",
        object_type="gate.record",
        object_id="gaterec_123456789abc",
        payload={"fixture": True},
        event_type="fixture.gate_recorded",
    )
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "delivery ready"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)
    monkeypatch.setattr(
        "aiscience.cli._central_g2_approval",
        lambda _repo, _project: (
            {"gate_record_ref": gate_ref.model_dump(mode="json")},
            [],
        ),
    )
    monkeypatch.setattr(
        "aiscience.delivery.finalize_package",
        lambda *_args, **_kwargs: {
            "status": "awaiting_completion_tag",
            "package_id": "pkg_1234567890abcdef",
            "final_path": "delivery/final/pkg_1234567890abcdef",
            "manifest_sha256": "a" * 64,
            "g2_approval_sha256": "b" * 64,
            "tag": {
                "created": False,
                "name": "aiscience-study-01-pkg_1234567890abcdef",
            },
        },
    )

    result = CliRunner().invoke(app, ["package", "finalize", "study-01"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    completion_commit = payload["data"]["completion_commit"]
    assert ProjectState.model_validate(store.read_state()).stage is ProjectStage.DELIVERED
    assert subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout == ""
    tag_type = subprocess.run(
        [
            "git",
            "cat-file",
            "-t",
            "refs/tags/aiscience-study-01-pkg_1234567890abcdef",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tagged_commit = subprocess.run(
        [
            "git",
            "rev-list",
            "-n",
            "1",
            "aiscience-study-01-pkg_1234567890abcdef",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert tag_type == "tag"
    assert tagged_commit == completion_commit


def _finalize_failure_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, LedgerStore, str]:
    _git_repo(tmp_path)
    project = tmp_path / "projects" / "study-01"
    store = LedgerStore(project)
    store.write_state(
        ProjectState(
            project_id="study-01", stage=ProjectStage.DELIVERY_READY
        ).model_dump(mode="json")
    )
    manifest = project / "delivery" / "candidate" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"package_id": "pkg_1234567890abcdef"}), encoding="utf-8"
    )
    gate_ref = store.commit_object(
        project_id="study-01",
        object_type="gate.record",
        object_id="gaterec_123456789abc",
        payload={"fixture": True},
        event_type="fixture.gate_recorded",
    )
    (tmp_path / ".gitignore").write_text(
        "projects/*/delivery/final/\n", encoding="utf-8"
    )
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "delivery ready"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    original_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setattr("aiscience.cli._repo", lambda: tmp_path)
    monkeypatch.setattr(
        "aiscience.cli._central_g2_approval",
        lambda _repo, _project: (
            {"gate_record_ref": gate_ref.model_dump(mode="json")},
            [],
        ),
    )

    def fake_finalize(*_args: object, **_kwargs: object) -> dict[str, object]:
        final = project / "delivery" / "final" / "pkg_1234567890abcdef"
        final.mkdir(parents=True)
        (final / "manifest.json").write_text("{}", encoding="utf-8")
        return {
            "status": "awaiting_completion_tag",
            "package_id": "pkg_1234567890abcdef",
            "final_path": "delivery/final/pkg_1234567890abcdef",
            "manifest_sha256": "a" * 64,
            "g2_approval_sha256": "b" * 64,
            "tag": {
                "created": False,
                "name": "aiscience-study-01-pkg_1234567890abcdef",
            },
        }

    monkeypatch.setattr("aiscience.delivery.finalize_package", fake_finalize)
    return project, store, original_head


def test_package_finalize_tag_collision_has_no_side_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, store, original_head = _finalize_failure_fixture(tmp_path, monkeypatch)
    tag = "aiscience-study-01-pkg_1234567890abcdef"
    subprocess.run(["git", "tag", "-a", tag, "-m", "collision"], cwd=tmp_path, check=True)

    result = CliRunner().invoke(app, ["package", "finalize", "study-01"])

    assert result.exit_code == int(ExitCode.PRECONDITION)
    assert json.loads(result.output)["errors"][0]["code"] == "COMPLETION_TAG_EXISTS"
    assert ProjectState.model_validate(store.read_state()).stage is ProjectStage.DELIVERY_READY
    assert not (project / "delivery" / "final" / "pkg_1234567890abcdef").exists()
    assert not any(event.event_type == "delivery.finalized" for event in store.events())
    assert subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.strip() == original_head


def test_package_finalize_commit_failure_rolls_back_all_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, store, original_head = _finalize_failure_fixture(tmp_path, monkeypatch)
    from aiscience import cli as cli_module

    original_command = cli_module._completion_git

    def fail_commit_tree(
        repo_root: Path, *arguments: str, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        if arguments and arguments[0] == "commit-tree":
            return subprocess.CompletedProcess(arguments, 1, "", "injected failure")
        return original_command(repo_root, *arguments, input_text=input_text)

    monkeypatch.setattr("aiscience.cli._completion_git", fail_commit_tree)
    result = CliRunner().invoke(app, ["package", "finalize", "study-01"])

    payload = json.loads(result.output)
    assert result.exit_code == int(ExitCode.INTEGRITY)
    assert payload["data"]["rolled_back"] is True
    assert ProjectState.model_validate(store.read_state()).stage is ProjectStage.DELIVERY_READY
    assert not any(event.event_type == "delivery.finalized" for event in store.events())
    assert not (project / "delivery" / "final" / "pkg_1234567890abcdef").exists()
    assert subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.strip() == original_head
    assert subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout == ""
