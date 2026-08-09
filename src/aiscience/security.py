"""Fail-closed scanning and non-identifying redaction for persisted text."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .integrity import canonical_json, sha256_bytes


class UnsafeContentError(ValueError):
    """Content may not be written to the tracked ledger without remediation."""


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    (
        "GENERIC_SECRET",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_])['\"]?"
            r"(?:api[_-]?key|secret|password|passwd|token)['\"]?"
            r"\s*[:=]\s*['\"]?[^\s,'\"]{8,}"
        ),
    ),
    ("EMAIL", re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")),
    ("PRC_ID", re.compile(r"(?<![A-Za-z0-9])\d{17}[0-9Xx](?![A-Za-z0-9])")),
    (
        "PHONE",
        re.compile(r"(?<![A-Za-z0-9])(?:\+?86[- ]?)?1[3-9]\d{9}(?![A-Za-z0-9])"),
    ),
)


def scan_text(text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for kind, pattern in _PATTERNS:
        findings.extend(
            Finding(kind, match.start(), match.end()) for match in pattern.finditer(text)
        )
    return tuple(
        sorted(findings, key=lambda finding: (finding.start, -(finding.end - finding.start)))
    )


def redact_text(text: str) -> tuple[str, tuple[str, ...]]:
    """Remove matches without retaining a digest of the sensitive original."""

    findings = scan_text(text)
    if not findings:
        return text, ()
    selected: list[Finding] = []
    cursor = -1
    for finding in findings:
        if finding.start >= cursor:
            selected.append(finding)
            cursor = finding.end
    chunks: list[str] = []
    cursor = 0
    kinds: list[str] = []
    for finding in selected:
        chunks.append(text[cursor : finding.start])
        chunks.append(f"[REDACTED:{finding.kind}]")
        kinds.append(finding.kind)
        cursor = finding.end
    chunks.append(text[cursor:])
    return "".join(chunks), tuple(kinds)


def assert_safe_text(text: str) -> None:
    findings = scan_text(text)
    if findings:
        kinds = sorted({finding.kind for finding in findings})
        raise UnsafeContentError(f"sensitive content detected: {', '.join(kinds)}")


def assert_safe_value(value: Any) -> None:
    """Scan the exact UTF-8 representation that would enter Git."""

    assert_safe_text(canonical_json(value).decode("utf-8"))


def safe_digest_secret(value: str, *, sensitive: bool, min_entropy_chars: int = 32) -> str:
    """Hash only non-sensitive or sufficiently high-entropy opaque material.

    This guard prevents callers from treating a plain SHA-256 of a password, email,
    identifier, or similarly enumerable value as anonymization.
    """

    if sensitive and (len(value) < min_entropy_chars or len(set(value)) < 12):
        raise UnsafeContentError("refusing an unsalted SHA-256 of low-entropy sensitive data")
    return sha256_bytes(value.encode("utf-8"))


def finding_kinds(findings: Iterable[Finding]) -> tuple[str, ...]:
    return tuple(sorted({finding.kind for finding in findings}))
