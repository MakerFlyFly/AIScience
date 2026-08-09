"""Canonical serialization, SHA-256 helpers, and framed event parsing."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .models import EventRecord

ZERO_HASH = ""
HEADER_SIZE = 8
TRAILER_SIZE = 64


class IntegrityError(RuntimeError):
    """The ledger is structurally invalid or content has changed."""


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("naive timestamps cannot be canonicalized")
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, float) and (
        value != value or value in (float("inf"), float("-inf"))
    ):
        raise ValueError("non-finite floats are forbidden in canonical JSON")
    return value


def canonical_json(value: Any) -> bytes:
    """Serialize with deterministic UTF-8 JSON suitable for content addressing."""

    return json.dumps(
        _jsonable(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_object(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def event_content_hash(event: EventRecord | Mapping[str, Any]) -> str:
    """Hash an event excluding its self-referential ``event_hash`` field."""

    data = event.model_dump(mode="json") if isinstance(event, EventRecord) else dict(event)
    data.pop("event_hash", None)
    return sha256_object(data)


def encode_frame(event: EventRecord) -> bytes:
    """Encode ``length:payload:payload_sha256\n``.

    A digest inside the event protects the event semantics; the frame digest and
    fixed-width length make torn writes recoverable without guessing boundaries.
    """

    if event.event_hash != event_content_hash(event):
        raise IntegrityError("event_hash does not match event content")
    payload = canonical_json(event)
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("event is too large for the frame format")
    return (
        f"{len(payload):08x}:".encode("ascii")
        + payload
        + b":"
        + sha256_bytes(payload).encode()
        + b"\n"
    )


@dataclass(frozen=True)
class FrameReadResult:
    events: tuple[EventRecord, ...]
    valid_size: int
    corrupt_tail: bytes


def read_frames(data: bytes, *, verify_chain: bool = True) -> FrameReadResult:
    """Read all complete valid frames and return an invalid/torn suffix separately."""

    events: list[EventRecord] = []
    offset = 0
    previous_hash = ZERO_HASH
    while offset < len(data):
        start = offset
        if len(data) - offset < HEADER_SIZE + 1:
            break
        header = data[offset : offset + HEADER_SIZE]
        if data[offset + HEADER_SIZE : offset + HEADER_SIZE + 1] != b":":
            break
        try:
            length = int(header, 16)
        except ValueError:
            break
        payload_start = offset + HEADER_SIZE + 1
        payload_end = payload_start + length
        frame_end = payload_end + 1 + TRAILER_SIZE + 1
        if frame_end > len(data):
            break
        if data[payload_end : payload_end + 1] != b":" or data[frame_end - 1 : frame_end] != b"\n":
            break
        payload = data[payload_start:payload_end]
        claimed = data[payload_end + 1 : frame_end - 1]
        if claimed != sha256_bytes(payload).encode("ascii"):
            break
        try:
            raw = json.loads(payload)
            event = EventRecord.model_validate(raw)
        except (json.JSONDecodeError, ValueError):
            break
        if canonical_json(raw) != payload:
            break
        if event.event_hash != event_content_hash(event):
            break
        if verify_chain and event.previous_hash != previous_hash:
            break
        events.append(event)
        previous_hash = event.event_hash
        offset = frame_end
        if offset <= start:  # Defensive; cannot happen with the format above.
            raise IntegrityError("frame parser made no progress")
    return FrameReadResult(tuple(events), offset, data[offset:])


def read_event_file(path: Path, *, verify_chain: bool = True) -> FrameReadResult:
    if not path.exists():
        return FrameReadResult((), 0, b"")
    return read_frames(path.read_bytes(), verify_chain=verify_chain)
