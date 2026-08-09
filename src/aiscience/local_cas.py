"""Git-ignored local content-addressed storage for restricted run outputs."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path
from typing import Any

from .security import scan_text
from .storage import atomic_write

CAS_THRESHOLD_BYTES = 10 * 1024 * 1024
_HEX_DIGEST = frozenset("0123456789abcdef")
_TEXT_SUFFIXES = {
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _hmac_sha256(path: Path, key: bytes) -> str:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _cas_key(data_root: Path) -> bytes:
    path = data_root / "cas.key"
    if path.exists():
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError("本地 CAS 密钥长度无效")
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(os.urandom(32))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        pass
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("本地 CAS 密钥创建失败")
    return key


class LocalCASIntegrityError(ValueError):
    """A tracked CAS manifest or its local blob cannot be verified."""

    def __init__(self, code: str, message_zh: str) -> None:
        super().__init__(message_zh)
        self.code = code
        self.message_zh = message_zh


def _existing_cas_key(data_root: Path) -> bytes:
    """Read an existing key without creating files or directories."""

    path = data_root / "cas.key"
    try:
        key = path.read_bytes()
    except FileNotFoundError as exc:
        raise LocalCASIntegrityError("CAS_KEY_MISSING", "本地 CAS 校验密钥不存在。") from exc
    except OSError as exc:
        raise LocalCASIntegrityError("CAS_KEY_UNREADABLE", "本地 CAS 校验密钥无法读取。") from exc
    if len(key) != 32:
        raise LocalCASIntegrityError("CAS_KEY_INVALID", "本地 CAS 校验密钥长度无效。")
    return key


def validate_local_cas_manifest(
    project_root: Path,
    manifest_path: Path,
    *,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify a tracked manifest and its blob without mutating local CAS state."""

    project_root = project_root.resolve()
    manifest_path = manifest_path.resolve()
    try:
        manifest_path.relative_to(project_root)
    except ValueError as exc:
        raise LocalCASIntegrityError(
            "CAS_MANIFEST_PATH_INVALID", "CAS manifest 越出项目边界。"
        ) from exc
    if not manifest_path.is_file():
        raise LocalCASIntegrityError("CAS_MANIFEST_MISSING", "CAS manifest 不存在。")
    if expected_manifest_sha256 is not None:
        if (
            len(expected_manifest_sha256) != 64
            or set(expected_manifest_sha256) - _HEX_DIGEST
        ):
            raise LocalCASIntegrityError(
                "CAS_MANIFEST_EXPECTED_HASH_INVALID", "CAS manifest 预期哈希无效。"
            )
        if not hmac.compare_digest(_sha256(manifest_path), expected_manifest_sha256):
            raise LocalCASIntegrityError(
                "CAS_MANIFEST_HASH_MISMATCH", "CAS manifest 与台账哈希不一致。"
            )
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LocalCASIntegrityError("CAS_MANIFEST_INVALID", "CAS manifest 无法解析。") from exc
    if not isinstance(value, dict):
        raise LocalCASIntegrityError("CAS_MANIFEST_INVALID", "CAS manifest 必须是对象。")
    algorithm = value.get("algorithm")
    digest = value.get("digest")
    address = value.get("address")
    size = value.get("size_bytes")
    original_path = value.get("original_path")
    sensitive = value.get("sensitive")
    redistributable = value.get("redistributable")
    if value.get("schema_version") != "1.0" or value.get("kind") != "local_cas_mount":
        raise LocalCASIntegrityError("CAS_MANIFEST_SCHEMA", "CAS manifest 类型或版本无效。")
    if algorithm not in {"sha256", "hmac-sha256"}:
        raise LocalCASIntegrityError("CAS_ALGORITHM_INVALID", "CAS manifest 算法无效。")
    if not isinstance(digest, str) or len(digest) != 64 or set(digest) - _HEX_DIGEST:
        raise LocalCASIntegrityError("CAS_DIGEST_INVALID", "CAS manifest 摘要无效。")
    if address != f"{algorithm}:{digest}":
        raise LocalCASIntegrityError("CAS_ADDRESS_MISMATCH", "CAS 地址与算法/摘要不一致。")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise LocalCASIntegrityError("CAS_SIZE_INVALID", "CAS manifest 文件大小无效。")
    if not isinstance(sensitive, bool) or not isinstance(redistributable, bool):
        raise LocalCASIntegrityError("CAS_POLICY_INVALID", "CAS manifest 策略字段无效。")
    if not isinstance(original_path, str) or not original_path:
        raise LocalCASIntegrityError("CAS_ORIGINAL_PATH_INVALID", "CAS 原始相对路径无效。")
    original = Path(original_path)
    if original.is_absolute() or ".." in original.parts:
        raise LocalCASIntegrityError("CAS_ORIGINAL_PATH_INVALID", "CAS 原始路径越界。")
    public_sha256 = value.get("sha256")
    if algorithm == "sha256":
        if public_sha256 != digest or sensitive:
            raise LocalCASIntegrityError("CAS_POLICY_MISMATCH", "普通 CAS 摘要或敏感标记不一致。")
        key = None
    else:
        if public_sha256 is not None or not sensitive:
            raise LocalCASIntegrityError("CAS_POLICY_MISMATCH", "敏感 CAS 策略与 HMAC 不一致。")
        key = _existing_cas_key(project_root / ".aiscience-data")
    blob = project_root / ".aiscience-data" / "cas" / str(algorithm) / digest[:2] / digest
    try:
        blob.resolve().relative_to(project_root)
    except ValueError as exc:
        raise LocalCASIntegrityError("CAS_BLOB_PATH_INVALID", "CAS blob 越出项目边界。") from exc
    if not blob.is_file():
        raise LocalCASIntegrityError("CAS_BLOB_MISSING", "CAS blob 不存在。")
    if blob.stat().st_size != size:
        raise LocalCASIntegrityError("CAS_BLOB_SIZE_MISMATCH", "CAS blob 大小与 manifest 不一致。")
    actual = _hmac_sha256(blob, key) if key is not None else _sha256(blob)
    if not hmac.compare_digest(actual, digest):
        raise LocalCASIntegrityError("CAS_BLOB_HASH_MISMATCH", "CAS blob 完整性校验失败。")
    return value


def _scan_output(path: Path) -> tuple[str, ...]:
    if path.suffix.lower() not in _TEXT_SUFFIXES:
        return ()
    kinds: set[str] = set()
    carry = b""
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            window = carry + block
            text = window.decode("utf-8", errors="replace")
            for finding in scan_text(text):
                # Scientific decimal output can contain 11 or 18 consecutive digits.
                # A decimal point adjacent to the match rules out a phone/PRC-ID token.
                before = text[finding.start - 1] if finding.start else ""
                after = text[finding.end] if finding.end < len(text) else ""
                if finding.kind in {"PRC_ID", "PHONE"} and (before == "." or after == "."):
                    continue
                kinds.add(finding.kind)
            carry = window[-4096:]
    return tuple(sorted(kinds))


def _copy_verified(source: Path, destination: Path, expected: str, *, key: bytes | None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        actual = _hmac_sha256(destination, key) if key is not None else _sha256(destination)
        if actual != expected:
            raise ValueError("本地 CAS 地址发生完整性冲突")
        return
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        with source.open("rb") as reader, temporary.open("xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
        actual = _hmac_sha256(temporary, key) if key is not None else _sha256(temporary)
        if actual != expected:
            raise ValueError("写入本地 CAS 后完整性校验失败")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def archive_output(
    *,
    project_root: Path,
    run_root: Path,
    output_path: Path,
    relative_path: str,
    declared_sensitive: bool,
    redistributable: bool,
) -> dict[str, Any]:
    """Archive one output and return a Git-safe manifest record.

    Sensitive output uses a keyed HMAC address, so the tracked record never stores
    a dictionary-attackable ordinary SHA-256 of low-entropy private material.
    """

    size = output_path.stat().st_size
    findings = _scan_output(output_path)
    sensitive = declared_sensitive or bool(findings)
    use_cas = size > CAS_THRESHOLD_BYTES or sensitive or not redistributable
    relative = relative_path.replace("\\", "/")
    if not use_cas:
        digest = _sha256(output_path)
        archive = run_root / "artifacts" / relative
        archive.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(output_path, archive)
        if _sha256(archive) != digest:
            raise ValueError(f"artifact_copy_integrity:{relative}")
        return {
            "path": relative,
            "sha256": digest,
            "size_bytes": size,
            "archived_path": archive.relative_to(run_root).as_posix(),
            "storage_policy": "git_eligible",
            "sensitive": False,
            "redistributable": True,
            "scan_findings": [],
        }

    data_root = project_root / ".aiscience-data"
    if sensitive:
        key = _cas_key(data_root)
        algorithm = "hmac-sha256"
        digest = _hmac_sha256(output_path, key)
        public_sha256: str | None = None
    else:
        key = None
        algorithm = "sha256"
        digest = _sha256(output_path)
        public_sha256 = digest
    destination = data_root / "cas" / algorithm / digest[:2] / digest
    _copy_verified(output_path, destination, digest, key=key)

    manifest_path = run_root / "artifacts" / f"{relative}.cas.json"
    manifest = {
        "schema_version": "1.0",
        "kind": "local_cas_mount",
        "original_path": relative,
        "address": f"{algorithm}:{digest}",
        "algorithm": algorithm,
        "digest": digest,
        "sha256": public_sha256,
        "size_bytes": size,
        "sensitive": sensitive,
        "redistributable": redistributable,
        "scan_findings": list(findings),
        "mount_instruction_zh": (
            "使用本机 .aiscience-data/cas 中的地址恢复；该内容不得进入 Git 或交付包。"
        ),
    }
    atomic_write(
        manifest_path,
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
    )
    output_path.unlink()
    return {
        "path": relative,
        "sha256": public_sha256,
        "size_bytes": size,
        "archived_path": None,
        "cas_manifest_path": manifest_path.relative_to(run_root).as_posix(),
        "cas_address": f"{algorithm}:{digest}",
        "storage_policy": "local_cas",
        "sensitive": sensitive,
        "redistributable": redistributable,
        "scan_findings": list(findings),
    }


__all__ = [
    "CAS_THRESHOLD_BYTES",
    "LocalCASIntegrityError",
    "archive_output",
    "validate_local_cas_manifest",
]
