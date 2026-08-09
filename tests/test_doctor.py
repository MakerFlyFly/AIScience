import subprocess
from pathlib import Path

import pytest

from aiscience.doctor import _tool_version, collect_doctor_report
from aiscience.envelope import envelope


def test_envelope_has_stable_shape() -> None:
    result = envelope(ok=True, command="test", project_id="demo", data={"value": 1})
    assert list(result) == ["ok", "command", "project_id", "data", "errors", "warnings"]
    assert result["errors"] == []


def test_doctor_reports_observed_python_and_git(tmp_path: Path) -> None:
    report = collect_doctor_report(tmp_path)
    assert report["python"]["capture_status"] == "observed"
    assert report["git"]["capture_status"] == "observed"
    assert "tools" in report
    assert "blockers" in report


def test_doctor_does_not_report_a_failing_tool_as_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("aiscience.doctor.shutil.which", lambda _name: "broken-tool")
    monkeypatch.setattr(
        "aiscience.doctor.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "broken"),
    )

    result = _tool_version("pdfinfo", "-v")

    assert result["capture_status"] == "observed"
    assert result["version"] == "unavailable"
