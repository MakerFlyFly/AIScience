"""Environment capability discovery without overstating enforcement guarantees."""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _tool_version(name: str, *args: str) -> dict[str, str]:
    candidates = (f"{name}.exe", name) if os.name == "nt" else (name,)
    failures: list[str] = []
    last_path = ""
    for candidate in candidates:
        executable = shutil.which(candidate)
        if executable is None or executable == last_path:
            continue
        last_path = executable
        try:
            completed = subprocess.run(
                [executable, *args],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append(type(exc).__name__)
            continue
        if completed.returncode != 0:
            failures.append(f"exit_{completed.returncode}")
            continue
        line = (completed.stdout or completed.stderr).splitlines()
        version = line[0].strip() if line else "unknown"
        return {"capture_status": "observed", "path": executable, "version": version}
    return {
        "capture_status": "observed",
        "path": last_path,
        "version": "unavailable",
        "error": ",".join(failures) if failures else "not_found",
    }


def _windows_drive_type(path: Path) -> tuple[str, bool]:
    if os.name != "nt":
        return "not_applicable", True
    root = Path(path.anchor or path.resolve().anchor)
    drive_type = ctypes.windll.kernel32.GetDriveTypeW(str(root))
    names = {
        0: "unknown",
        1: "no_root",
        2: "removable",
        3: "fixed",
        4: "remote",
        5: "cdrom",
        6: "ramdisk",
    }
    return names.get(int(drive_type), "unknown"), int(drive_type) == 3


def _git_status(repo_root: Path) -> dict[str, Any]:
    git = shutil.which("git")
    if git is None:
        return {"available": False, "is_repository": False, "capture_status": "observed"}
    check = subprocess.run(
        [git, "-C", str(repo_root), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return {
        "available": True,
        "is_repository": check.returncode == 0,
        "root": check.stdout.strip() if check.returncode == 0 else "",
        "capture_status": "observed",
    }


def collect_doctor_report(repo_root: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    drive_type, local_fixed = _windows_drive_type(repo_root)
    tools = {
        "git": _tool_version("git", "--version"),
        "uv": _tool_version("uv", "--version"),
        "pandoc": _tool_version("pandoc", "--version"),
        "xelatex": _tool_version("xelatex", "--version"),
        "latexmk": _tool_version("latexmk", "-version"),
        "pdftoppm": _tool_version("pdftoppm", "-v"),
        "pdfinfo": _tool_version("pdfinfo", "-v"),
        "codex": _tool_version("codex", "--version"),
    }
    blockers: list[dict[str, str]] = []
    if sys.version_info[:2] != (3, 12):
        blockers.append({"code": "PYTHON_VERSION", "message_zh": "正式工作流要求 Python 3.12。"})
    git_status = _git_status(repo_root)
    if not git_status["is_repository"]:
        blockers.append({"code": "NOT_GIT_REPOSITORY", "message_zh": "工作目录不是 Git 仓库。"})
    if os.name == "nt" and not local_fixed:
        blockers.append(
            {"code": "UNSUPPORTED_FILESYSTEM", "message_zh": "正式项目仅支持本地固定磁盘。"}
        )
    for required in ("uv", "pandoc", "xelatex", "pdfinfo", "pdftoppm"):
        if tools[required]["version"] == "unavailable":
            blockers.append(
                {"code": f"MISSING_{required.upper()}", "message_zh": f"缺少 {required}。"}
            )
    return {
        "ready": not blockers,
        "repo_root": str(repo_root),
        "python": {
            "capture_status": "observed",
            "version": platform.python_version(),
            "executable": sys.executable,
        },
        "platform": {
            "capture_status": "observed",
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "drive_type": drive_type,
        },
        "git": git_status,
        "tools": tools,
        "blockers": blockers,
        "notes": [
            "工具版本只表示本次实际探测结果。",
            "Codex 指令加载、模型和完整工具轨迹在不可观测时必须记录为 unknown。",
        ],
    }
