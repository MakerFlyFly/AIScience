"""Scan research content that is tracked or staged for Git."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from .security import scan_text

_TEXT_SUFFIXES = {
    ".bib",
    ".csv",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".py",
    ".tex",
    ".tsv",
    ".txt",
    ".yaml",
    ".yml",
}
_ABSOLUTE_PATHS = (
    re.compile(r"(?i)(?<![A-Za-z0-9])(?:[A-Z]:\\(?:[^\s\"'<>|]+\\)*[^\s\"'<>|]*)"),
    re.compile(r"(?<![A-Za-z0-9])/(?:home|Users|mnt|var/tmp|tmp)/[^\s\"'<>]+"),
)


def _git_bytes(repo_root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise OSError(completed.stderr.decode("utf-8", errors="replace").strip())
    return completed.stdout


def _paths(repo_root: Path, *args: str) -> tuple[str, ...]:
    output = _git_bytes(repo_root, *args)
    return tuple(
        item.decode("utf-8", errors="strict")
        for item in output.split(b"\0")
        if item
    )


def _scan_blob(path: str, source: str, data: bytes) -> list[dict[str, Any]]:
    if Path(path).suffix.lower() not in _TEXT_SUFFIXES:
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [
            {
                "code": "GIT_TEXT_ENCODING",
                "message_zh": "拟进入 Git 的研究文本不是 UTF-8。",
                "details": {"path": path, "source": source},
            }
        ]
    findings: list[dict[str, Any]] = []
    for finding in scan_text(text):
        before = text[finding.start - 1] if finding.start else ""
        after = text[finding.end] if finding.end < len(text) else ""
        if finding.kind in {"PRC_ID", "PHONE"} and (before == "." or after == "."):
            continue
        findings.append(
            {
                "code": "GIT_SECRET_OR_PII",
                "message_zh": "拟进入 Git 的研究文本含疑似秘密或个人信息。",
                "details": {"path": path, "source": source, "kind": finding.kind},
            }
        )
    if any(pattern.search(text) for pattern in _ABSOLUTE_PATHS):
        findings.append(
            {
                "code": "GIT_LOCAL_ABSOLUTE_PATH",
                "message_zh": "拟进入 Git 的研究文本含本机绝对路径。",
                "details": {"path": path, "source": source},
            }
        )
    return findings


def scan_git_project_content(repo_root: Path, project_id: str) -> list[dict[str, Any]]:
    """Return findings for worktree and staged blobs below one project boundary."""

    repo_root = Path(repo_root).resolve()
    project_prefix = f"projects/{project_id}/"
    findings: list[dict[str, Any]] = []
    tracked = _paths(repo_root, "ls-files", "-z", "--", project_prefix)
    for relative in tracked:
        path = (repo_root / relative).resolve()
        try:
            path.relative_to((repo_root / "projects" / project_id).resolve())
        except ValueError:
            findings.append(
                {
                    "code": "GIT_SCAN_PATH_ESCAPE",
                    "message_zh": "Git 研究路径越出项目边界。",
                    "details": {"path": relative, "source": "working_tree"},
                }
            )
            continue
        if path.is_file():
            findings.extend(_scan_blob(relative, "working_tree", path.read_bytes()))

    staged = _paths(
        repo_root,
        "diff",
        "--cached",
        "--name-only",
        "--diff-filter=ACMR",
        "-z",
        "--",
        project_prefix,
    )
    for relative in staged:
        staged_blob = _git_bytes(repo_root, "show", f":{relative}")
        findings.extend(_scan_blob(relative, "index", staged_blob))
    return findings


__all__ = ["scan_git_project_content"]
