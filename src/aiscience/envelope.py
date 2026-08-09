"""Stable JSON envelopes and exit codes for the CLI."""

from __future__ import annotations

import json
from enum import IntEnum
from typing import Any, NoReturn

import typer


class ExitCode(IntEnum):
    OK = 0
    INPUT = 2
    PRECONDITION = 3
    UNAVAILABLE = 4
    INTEGRITY = 5


def envelope(
    *,
    ok: bool,
    command: str,
    project_id: str | None = None,
    data: dict[str, Any] | None = None,
    errors: list[dict[str, Any]] | None = None,
    warnings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "ok": ok,
        "command": command,
        "project_id": project_id,
        "data": data or {},
        "errors": errors or [],
        "warnings": warnings or [],
    }


def emit(payload: dict[str, Any]) -> None:
    typer.echo(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))


def fail(
    *,
    command: str,
    code: str,
    message_zh: str,
    exit_code: ExitCode,
    project_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> NoReturn:
    emit(
        envelope(
            ok=False,
            command=command,
            project_id=project_id,
            errors=[{"code": code, "message_zh": message_zh, "details": details or {}}],
        )
    )
    raise typer.Exit(code=int(exit_code))

