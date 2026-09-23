"""Minimize submitted metadata; redaction is not a data-loss-prevention guarantee."""

import re
import unicodedata
from collections.abc import Iterator

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


def sanitize_process(process: Process, include_command_line: bool) -> Process:
    # Work at the external-input boundary and revalidate the transformed record.
    # A replacement such as <redacted> can be longer than the original secret.
    data = process.model_dump(mode="python")
    coverage = data["coverage"]

    def clean(value: str, limit: int, source: str) -> str:
        result = redact_text(value)
        if len(result) > limit:
            coverage[source] = "truncated"
            return result[:limit]
        return result

    data["name"] = clean(process.name, 512, "name")
    data["status"] = clean(process.status, 512, "status")
    if process.executable is not None:
        data["executable"] = clean(process.executable, 8192, "executable")
    if process.file.signature_identifier is not None:
        data["file"]["signature_identifier"] = clean(process.file.signature_identifier, 512, "signature")
    if process.file.signature_team_id is not None:
        data["file"]["signature_team_id"] = clean(process.file.signature_team_id, 512, "signature")
    data["file"]["signature_authorities"] = [
        clean(value, 512, "signature") for value in process.file.signature_authorities
    ]
    for parent in data["ancestors"]:
        parent["name"] = clean(parent["name"], 512, "ancestry")
        if parent["executable"] is not None:
            parent["executable"] = clean(parent["executable"], 8192, "ancestry")
    for child in data["children"]:
        child["name"] = clean(child["name"], 512, "children")
        if child["executable"] is not None:
            child["executable"] = clean(child["executable"], 8192, "children")
        child["status"] = clean(child["status"], 512, "children")
    for connection in data["connections"]:
        for key in ("local_address", "remote_address", "status"):
            connection[key] = clean(connection[key], 512, "connections")
    data["observations"] = [clean(value, 512, "observations") for value in process.observations]
    if include_command_line and process.command_line is not None:
        argv, shortened = redact_argv(process.command_line)
        data["command_line"] = argv
        if shortened:
            coverage["command_line"] = "truncated"
    else:
        data["command_line"] = None
        coverage["command_line"] = "not_requested"
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
