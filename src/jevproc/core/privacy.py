"""Minimize submitted metadata; redaction is not a data-loss-prevention guarantee."""

import re
import unicodedata
from collections.abc import Iterator
from typing import Any

from jevproc.core.models import Process, Snapshot

_SECRET_FLAGS = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "token",
    "access-token",
    "refresh-token",
    "api-key",
    "apikey",
    "secret",
    "client-secret",
    "authorization",
    "credential",
    "credentials",
    "cookie",
    "p",
    "h",
    "header",
}
_ASSIGNMENT = re.compile(
    r"(?i)((?:password|passwd|token|api[_-]?key|secret|authorization|credential|cookie)[\w.-]*\s*[:=]\s*)([^\s&;]+)"
)
_URL_AUTH = re.compile(r"(?i)(https?|ftp|socks5?)://[^\s/@]+(?::[^\s/@]*)?@")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9_+./=:-]+")
_KNOWN_KEY = re.compile(r"\b(?:jv_live_|sk-(?:proj-)?|gh[pousr]_)[A-Za-z0-9_-]{8,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_HOME = re.compile(r"(?<=/)(Users|home)/[^/\s]+")


def redact_text(text: str) -> str:
    text = _URL_AUTH.sub(lambda m: m.group(1) + "://<redacted>@", text)
    # Mask an authorization scheme's token before the assignment matcher can consume
    # the word 'Bearer' and leave its value behind.
    text = _BEARER.sub(lambda m: m.group(1) + " <redacted>", text)
    text = _ASSIGNMENT.sub(lambda m: m.group(1) + "<redacted>", text)
    text = _KNOWN_KEY.sub("<redacted>", text)
    text = _JWT.sub("<redacted>", text)
    return _HOME.sub(lambda m: m.group(1) + "/<user>", text)


def redact_argv(arguments: list[str]) -> tuple[list[str], bool]:
    """Apply positional redaction, text redaction, then independent wire bounds."""
    structurally_redacted = _structural_redactions(arguments[:64])
    text_redacted = (redact_text(value) for value in structurally_redacted)
    return _bound_arguments(text_redacted, arguments_truncated=len(arguments) > 64)


def _clean_value(value: str, limit: int, source: str, coverage: dict[str, Any]) -> str:
    result = redact_text(value)
    if len(result) <= limit:
        return result
    coverage[source] = "truncated"
    return result[:limit]


def _clean_optional(value: str | None, limit: int, source: str, coverage: dict[str, Any]) -> str | None:
    return None if value is None else _clean_value(value, limit, source, coverage)


def _sanitize_file(data: dict[str, Any], process: Process, coverage: dict[str, Any]) -> None:
    file_data = data["file"]
    file_data["signature_identifier"] = _clean_optional(process.file.signature_identifier, 512, "signature", coverage)
    file_data["signature_team_id"] = _clean_optional(process.file.signature_team_id, 512, "signature", coverage)
    file_data["signature_authorities"] = [
        _clean_value(value, 512, "signature", coverage) for value in process.file.signature_authorities
    ]


def _sanitize_ancestors(data: dict[str, Any], coverage: dict[str, Any]) -> None:
    for parent in data["ancestors"]:
        parent["name"] = _clean_value(parent["name"], 512, "ancestry", coverage)
        parent["executable"] = _clean_optional(parent["executable"], 8192, "ancestry", coverage)


def _sanitize_children(data: dict[str, Any], coverage: dict[str, Any]) -> None:
    for child in data["children"]:
        child["name"] = _clean_value(child["name"], 512, "children", coverage)
        child["executable"] = _clean_optional(child["executable"], 8192, "children", coverage)
        child["status"] = _clean_value(child["status"], 512, "children", coverage)


def _sanitize_connections(data: dict[str, Any], coverage: dict[str, Any]) -> None:
    for connection in data["connections"]:
        for key in ("local_address", "remote_address", "status"):
            connection[key] = _clean_value(connection[key], 512, "connections", coverage)


def _sanitize_command_line(
    data: dict[str, Any],
    process: Process,
    include_command_line: bool,
    coverage: dict[str, Any],
) -> None:
    if not include_command_line or process.command_line is None:
        data["command_line"] = None
        coverage["command_line"] = "not_requested"
        return
    argv, shortened = redact_argv(process.command_line)
    data["command_line"] = argv
    if shortened:
        coverage["command_line"] = "truncated"


def sanitize_process(process: Process, include_command_line: bool) -> Process:
    # Work at the external-input boundary and revalidate the transformed record.
    data = process.model_dump(mode="python")
    coverage = data["coverage"]
    data["name"] = _clean_value(process.name, 512, "name", coverage)
    data["status"] = _clean_value(process.status, 512, "status", coverage)
    data["executable"] = _clean_optional(process.executable, 8192, "executable", coverage)
    _sanitize_file(data, process, coverage)
    _sanitize_ancestors(data, coverage)
    _sanitize_children(data, coverage)
    _sanitize_connections(data, coverage)
    data["observations"] = [_clean_value(value, 512, "observations", coverage) for value in process.observations]
    _sanitize_command_line(data, process, include_command_line, coverage)
    return Process.model_validate(data)


def sanitize_snapshot(snapshot: Snapshot, include_command_line: bool) -> Snapshot:
    host = snapshot.host.model_copy(update={"architecture": redact_text(snapshot.host.architecture)[:512]})
    return snapshot.model_copy(
        update={
            "host": host,
            "processes": [sanitize_process(p, include_command_line) for p in snapshot.processes],
        }
    )


def terminal_text(text: str) -> str:
    """Escape ALL line/control/format characters so evidence cannot forge terminal rows."""
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} else char for char in text
    )


def _secret_flag(value: str) -> tuple[str, bool]:
    flag, separator, _ = value.partition("=")
    key = flag.lstrip("-").lower().replace("_", "-")
    if not flag.startswith("-") or key not in _SECRET_FLAGS:
        return value, False
    return (flag + "=<redacted>", False) if separator else (value, True)


def _structural_redactions(arguments: list[str]) -> Iterator[str]:
    """Redact split secret values using argv position only; no text matching here."""
    redact_next = False
    for index, value in enumerate(arguments):
        if redact_next:
            yield "<redacted>"
            redact_next = value.lower() in {"bearer", "basic"}
            continue
        if index == 0:
            yield value
            continue
        value, redact_next = _secret_flag(value)
        yield value


def _bound_argument(value: str) -> tuple[str, bool]:
    if len(value) <= 512:
        return value, False
    return value[:498] + "...<truncated>", True


def _bound_arguments(arguments: Iterator[str], *, arguments_truncated: bool) -> tuple[list[str], bool]:
    bounded: list[str] = []
    shortened = arguments_truncated
    for value in arguments:
        value, truncated = _bound_argument(value)
        bounded.append(value)
        shortened = shortened or truncated
    return bounded, shortened
