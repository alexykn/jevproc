"""On-disk metadata, bounded hashing, and macOS signature diagnostics."""

import hashlib
import os
import stat
import subprocess
import sys
from typing import Any

from jevproc.core.config import CollectionSettings
from jevproc.core.models import (
    Coverage,
    Executable,
)


def _hash_file(path: str, max_bytes: int) -> tuple[str | None, Coverage]:
    """Do not follow a final symlink or block on a FIFO/device substituted for a file."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                return None, "unavailable"
            if before.st_size > max_bytes:
                return None, "truncated"
            digest = hashlib.sha256()
            remaining = max_bytes + 1
            while remaining:
                block = handle.read(min(1024 * 1024, remaining))
                if not block:
                    break
                digest.update(block)
                remaining -= len(block)
            if remaining == 0:
                return None, "truncated"
            after = os.fstat(handle.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                return None, "partial"
            return digest.hexdigest(), "observed"
    except PermissionError:
        return None, "denied"
    except OSError:
        return None, "unavailable"


def _classify_codesign_failure(stderr: str) -> tuple[str, str | None]:
    """Normalize known diagnostics without treating unknown failures as valid."""
    text = stderr.lower()
    for phrases, state, issue in _CODESIGN_FAILURES:
        if any(phrase in text for phrase in phrases):
            return state, issue
    return "verification_failed", "other"


def _signature(path: str) -> tuple[dict[str, Any], Coverage]:
    if sys.platform != "darwin":
        return {"signature": "unavailable"}, "unavailable"
    try:
        verify = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", "--", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"signature": "unavailable"}, "unavailable"

    if verify.returncode == 0:
        values: dict[str, Any] = {"signature": "valid"}
    else:
        state, issue = _classify_codesign_failure(getattr(verify, "stderr", "") or "")
        values = {"signature": state}
        if issue is not None:
            values["signature_issue"] = issue
        if state == "unsigned":
            return values, "observed"

    # Display metadata is useful provenance even when integrity verification failed
    # or the signature uses a legacy resource envelope. It does not make the
    # verification result valid.
    try:
        display = subprocess.run(
            ["/usr/bin/codesign", "--display", "--verbose=4", "--", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return values, "observed"

    authorities: list[str] = []
    text = (getattr(display, "stdout", "") or "") + "\n" + (getattr(display, "stderr", "") or "")
    for line in text.splitlines():
        if line.startswith("Identifier="):
            values["signature_identifier"] = line.split("=", 1)[1][:512]
        elif line.startswith("TeamIdentifier="):
            team = line.split("=", 1)[1]
            if team and team != "not set":
                values["signature_team_id"] = team[:512]
        elif line.startswith("Authority=") and len(authorities) < 8:
            authorities.append(line.split("=", 1)[1][:512])
    values["signature_authorities"] = authorities
    # Verification and display are separate evidence: metadata never upgrades
    # a legacy or failed verification result to valid.
    return values, "observed"


def _file_info(
    path: str | None,
    settings: CollectionSettings,
    cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] | None = None,
) -> tuple[Executable, dict[str, Coverage]]:
    coverage = _file_coverage(settings)
    if not path or not os.path.isabs(path) or "\x00" in path:
        return Executable(), coverage
    metadata, coverage["file"], info = _stat_executable(path)
    if info is None:
        return metadata, coverage
    key = (path, *_file_identity(info), settings.hashes, settings.signatures, settings.max_hash_bytes)
    if cache is not None and key in cache:
        cached, cached_coverage = cache[key]
        return cached, dict(cached_coverage)
    inspected = _inspect_content(path, metadata, settings, coverage) if stat.S_ISREG(info.st_mode) else metadata
    if (settings.hashes or settings.signatures) and not _file_unchanged(path, info):
        # Never combine a file's old metadata with a replacement's inspection.
        return Executable(), {**_file_coverage(settings), "file": "partial"}
    if cache is not None:
        cache[key] = inspected, dict(coverage)
    return inspected, coverage


def _observations(path: str | None, info: Executable) -> list[str]:
    facts = []
    if path and any(path.startswith(prefix) for prefix in ("/tmp/", "/var/tmp/", "/private/tmp/")):
        facts.append(
            "Executable path is in a temporary directory; legitimate development and installers also use these."
        )
    if info.deleted:
        facts.append(
            "Linux reports a deleted executable image; updates and anonymous executable mappings can also cause this."
        )
    if info.mode is not None and info.mode & stat.S_IWOTH:
        facts.append("On-disk executable is world-writable; this is not proof of malicious execution.")
    if info.signature == "verification_failed":
        facts.append(
            "On-disk code-signature verification failed; unsigned or ad-hoc development code may be legitimate."
        )
    return facts


def _file_coverage(settings: CollectionSettings) -> dict[str, Coverage]:
    return {
        "file": "unavailable",
        "hash": "unavailable" if settings.hashes else "not_requested",
        "signature": "unavailable" if settings.signatures else "not_requested",
    }


def _stat_executable(path: str) -> tuple[Executable, Coverage, os.stat_result | None]:
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return Executable(exists=False), "observed", None
    except PermissionError:
        return Executable(), "denied", None
    except OSError:
        return Executable(), "unavailable", None
    return (
        Executable(
            exists=True,
            size=info.st_size,
            mode=stat.S_IMODE(info.st_mode),
            owner_uid=info.st_uid,
            modified_ns=info.st_mtime_ns,
        ),
        "observed",
        info,
    )


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _file_unchanged(path: str, before: os.stat_result) -> bool:
    try:
        return _file_identity(before) == _file_identity(os.stat(path))
    except OSError:
        return False


def _inspect_content(
    path: str, metadata: Executable, settings: CollectionSettings, coverage: dict[str, Coverage]
) -> Executable:
    values = metadata.model_dump()
    if settings.hashes:
        values["sha256"], coverage["hash"] = _hash_file(path, settings.max_hash_bytes)
    if settings.signatures:
        signature, coverage["signature"] = _signature(path)
        values.update(signature)
    return Executable.model_validate(values)


# Ordered codesign diagnostic mapping; first match retains historical precedence.
_CODESIGN_FAILURES: tuple[tuple[tuple[str, ...], str, str | None], ...] = (
    (("resource envelope is obsolete (custom omit rules)",), "legacy", "weak_resource_rules"),
    (("resource envelope is obsolete (version 1 signature)",), "legacy", "weak_resource_envelope"),
    (("code object is not signed",), "unsigned", None),
    (
        (
            "a sealed resource is missing or invalid",
            "sealed resource is missing or invalid",
            "invalid resource directory",
            "resource modified:",
            "resource missing:",
            "resource added:",
            "file modified:",
            "file missing:",
            "file added:",
        ),
        "verification_failed",
        "resource_modified",
    ),
    (
        (
            "nested code is modified or invalid",
            "embedded framework contains modified or invalid version",
            "nested code is unsigned",
        ),
        "verification_failed",
        "nested_code_invalid",
    ),
    (("code or signature modified",), "verification_failed", "signature_modified"),
    (
        (
            "does not satisfy its designated requirement",
            "failed to satisfy one of the code requirements",
            "code failed to satisfy specified code requirement",
        ),
        "verification_failed",
        "requirement_failed",
    ),
    (
        ("notarization indicates this code has been revoked", "cssmerr_tp_cert_revoked", "certificate was revoked"),
        "verification_failed",
        "revoked",
    ),
    (
        ("cssmerr_tp_cert_expired", "certificate has expired", "certificate expired"),
        "verification_failed",
        "certificate_expired",
    ),
    (
        (
            "bundle format is ambiguous",
            "bundle format unrecognized, invalid, or unsuitable",
            "object file format invalid or unsuitable",
            "required information property list",
        ),
        "verification_failed",
        "bundle_format_invalid",
    ),
    (
        (
            "main executable failed strict validation",
            "unsealed contents present",
            "invalid destination for symbolic link in bundle",
            "unsupported resource found",
            "must be a regular file",
        ),
        "verification_failed",
        "strict_validation_failed",
    ),
)
