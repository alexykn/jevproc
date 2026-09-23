"""On-disk metadata, bounded hashing, and macOS signature diagnostics."""

import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import Any

from jevproc.core.config import CollectionSettings
from jevproc.core.evidence.command import CommandResult, run_fixed
from jevproc.core.models import (
    Coverage,
    Executable,
)


def _hash_stream(handle, max_bytes: int) -> tuple[str | None, Coverage]:
    digest = hashlib.sha256()
    remaining = max_bytes + 1
    while remaining:
        block = handle.read(min(1024 * 1024, remaining))
        if not block:
            break
        digest.update(block)
        remaining -= len(block)
    return (None, "truncated") if remaining == 0 else (digest.hexdigest(), "observed")


def _hash_metadata_valid(info: os.stat_result, max_bytes: int) -> Coverage:
    if not stat.S_ISREG(info.st_mode):
        return "unavailable"
    return "truncated" if info.st_size > max_bytes else "observed"


def _hash_handle(handle, max_bytes: int) -> tuple[str | None, Coverage]:
    before = os.fstat(handle.fileno())
    metadata_state = _hash_metadata_valid(before, max_bytes)
    if metadata_state != "observed":
        return None, metadata_state
    digest, state = _hash_stream(handle, max_bytes)
    if state != "observed":
        return digest, state
    stable = _file_identity(before) == _file_identity(os.fstat(handle.fileno()))
    return (digest, "observed") if stable else (None, "partial")


def _hash_file(path: str, max_bytes: int) -> tuple[str | None, Coverage]:
    """Do not follow a final symlink or block on a FIFO/device substituted for a file."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            return _hash_handle(handle, max_bytes)
    except PermissionError:
        return None, "denied"
    except OSError:
        return None, "unavailable"


def _codesign_failure_matches(entry: tuple[tuple[str, ...], str, str | None], text: str) -> bool:
    phrases, _, _ = entry
    return any(phrase in text for phrase in phrases)


def _classify_codesign_failure(stderr: str) -> tuple[str, str | None]:
    """Normalize known diagnostics without treating unknown failures as valid."""
    text = stderr.lower()
    match = next(filter(lambda entry: _codesign_failure_matches(entry, text), _CODESIGN_FAILURES), None)
    return (match[1], match[2]) if match is not None else ("verification_failed", "other")


def _codesign_verify(path: str) -> CommandResult | None:
    return run_fixed(
        "/usr/bin/codesign",
        ("--verify", "--strict", "--", path),
        timeout=3,
    )


def _verification_values(verify) -> dict[str, Any]:
    if verify.returncode == 0:
        return {"signature": "valid"}
    state, issue = _classify_codesign_failure(getattr(verify, "stderr", "") or "")
    values: dict[str, Any] = {"signature": state}
    if issue is not None:
        values["signature_issue"] = issue
    return values


def _codesign_display(path: str) -> str | None:
    display = run_fixed(
        "/usr/bin/codesign",
        ("--display", "--verbose=4", "--", path),
        timeout=3,
    )
    if display is None:
        return None
    return display.stdout + "\n" + display.stderr


def _identifier_field(line: str) -> tuple[str, str] | None:
    prefix = "Identifier="
    return ("signature_identifier", line.removeprefix(prefix)[:512]) if line.startswith(prefix) else None


def _team_field(line: str) -> tuple[str, str] | None:
    prefix = "TeamIdentifier="
    if not line.startswith(prefix):
        return None
    value = line.removeprefix(prefix)
    return None if value == "not set" else ("signature_team_id", value[:512])


def _signature_field(line: str) -> tuple[str, str] | None:
    return _identifier_field(line) or _team_field(line)


def _signature_authorities(lines: list[str]) -> list[str]:
    return [line.split("=", 1)[1][:512] for line in lines if line.startswith("Authority=")][:8]


def _signature_identity(lines: list[str]) -> dict[str, str]:
    return dict(filter(None, map(_signature_field, lines)))


def _signature_metadata(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    return {
        **_signature_identity(lines),
        "signature_authorities": _signature_authorities(lines),
    }


def _display_signature_metadata(path: str, values: dict[str, Any]) -> dict[str, Any]:
    display = _codesign_display(path)
    if display is not None:
        values.update(_signature_metadata(display))
    return values


def _verified_signature(path: str) -> dict[str, Any] | None:
    verify = _codesign_verify(path)
    if verify is None:
        return None
    values = _verification_values(verify)
    return values if values["signature"] == "unsigned" else _display_signature_metadata(path, values)


def _signature(path: str) -> tuple[dict[str, Any], Coverage]:
    values = _verified_signature(path) if sys.platform == "darwin" else None
    return (values, "observed") if values is not None else ({"signature": "unavailable"}, "unavailable")


def _valid_file_path(path: str | None) -> bool:
    return bool(path and Path(path).is_absolute() and "\x00" not in path)


def _file_cache_key(path: str, info: os.stat_result, settings: CollectionSettings) -> tuple:
    return (path, *_file_identity(info), settings.hashes, settings.signatures, settings.max_hash_bytes)


def _cached_file(
    cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] | None,
    key: tuple,
) -> tuple[Executable, dict[str, Coverage]] | None:
    if cache is None or key not in cache:
        return None
    executable, coverage = cache[key]
    return executable, dict(coverage)


def _inspectable_content(
    path: str,
    metadata: Executable,
    info: os.stat_result,
    settings: CollectionSettings,
    coverage: dict[str, Coverage],
) -> Executable:
    return _inspect_content(path, metadata, settings, coverage) if stat.S_ISREG(info.st_mode) else metadata


def _inspection_stable(path: str, info: os.stat_result, settings: CollectionSettings) -> bool:
    requested = settings.hashes or settings.signatures
    return not requested or _file_unchanged(path, info)


def _inspect_stable_file(
    path: str,
    metadata: Executable,
    info: os.stat_result,
    settings: CollectionSettings,
    coverage: dict[str, Coverage],
) -> tuple[Executable, dict[str, Coverage], bool]:
    inspected = _inspectable_content(path, metadata, info, settings, coverage)
    stable = _inspection_stable(path, info, settings)
    partial_coverage: dict[str, Coverage] = {**_file_coverage(settings), "file": "partial"}
    partial = (Executable(), partial_coverage, False)
    return (inspected, coverage, True) if stable else partial


def _remember_file(
    cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] | None,
    key: tuple,
    executable: Executable,
    coverage: dict[str, Coverage],
) -> None:
    if cache is not None:
        cache[key] = executable, dict(coverage)


def _inspect_or_cached(
    path: str,
    metadata: Executable,
    info: os.stat_result,
    settings: CollectionSettings,
    coverage: dict[str, Coverage],
    cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] | None,
) -> tuple[Executable, dict[str, Coverage]]:
    key = _file_cache_key(path, info, settings)
    cached = _cached_file(cache, key)
    if cached is not None:
        return cached
    executable, final_coverage, stable = _inspect_stable_file(path, metadata, info, settings, coverage)
    if stable:
        _remember_file(cache, key, executable, final_coverage)
    return executable, final_coverage


def _file_info(
    path: str | None,
    settings: CollectionSettings,
    cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] | None = None,
) -> tuple[Executable, dict[str, Coverage]]:
    coverage = _file_coverage(settings)
    if not _valid_file_path(path):
        return Executable(), coverage
    assert path is not None
    metadata, coverage["file"], info = _stat_executable(path)
    return (metadata, coverage) if info is None else _inspect_or_cached(path, metadata, info, settings, coverage, cache)


def _temporary_path(path: str | None) -> bool:
    prefixes = ("/tmp/", "/var/tmp/", "/private/tmp/")
    return bool(path and path.startswith(prefixes))


def _world_writable(info: Executable) -> bool:
    return bool(info.mode is not None and info.mode & stat.S_IWOTH)


def _observations(path: str | None, info: Executable) -> list[str]:
    facts = (
        (
            _temporary_path(path),
            "Executable path is in a temporary directory; legitimate development and installers also use these.",
        ),
        (
            bool(info.deleted),
            "Linux reports a deleted executable image; updates and anonymous executable mappings can also cause this.",
        ),
        (
            _world_writable(info),
            "On-disk executable is world-writable; this is not proof of malicious execution.",
        ),
        (
            info.signature == "verification_failed",
            "On-disk code-signature verification failed; unsigned or ad-hoc development code may be legitimate.",
        ),
    )
    return [message for present, message in facts if present]


def _file_coverage(settings: CollectionSettings) -> dict[str, Coverage]:
    return {
        "file": "unavailable",
        "hash": "unavailable" if settings.hashes else "not_requested",
        "signature": "unavailable" if settings.signatures else "not_requested",
    }


def _stat_executable(path: str) -> tuple[Executable, Coverage, os.stat_result | None]:
    try:
        info = Path(path).stat()
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
        return _file_identity(before) == _file_identity(Path(path).stat())
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
