"""Minimize submitted metadata; redaction is not a data-loss-prevention guarantee."""

import re
import unicodedata

from jevproc.core.models import Process, Snapshot

_SECRET_FLAGS = {
    "password", "passwd", "pass", "pwd", "token", "access-token", "refresh-token", "api-key", "apikey",
    "secret", "client-secret", "authorization", "credential", "credentials", "cookie", "p", "h", "header",
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
    """Redact before bounding so a cut-off secret cannot defeat the recognizer."""
    result: list[str] = []
    redact_next = False
    shortened = len(arguments) > 64
    for index, value in enumerate(arguments[:64]):
        if redact_next:
            redact_next = value.lower() in {"bearer", "basic"}
            value = "<redacted>"
        elif index:
            flag, separator, _ = value.partition("=")
            if flag.startswith("-") and flag.lstrip("-").lower().replace("_", "-") in _SECRET_FLAGS:
                if separator:
                    value = flag + "=<redacted>"
                else:
                    redact_next = True
        cleaned = redact_text(value)
        if len(cleaned) > 512:
            cleaned = cleaned[:498] + "...<truncated>"
            shortened = True
        result.append(cleaned)
    return result, shortened


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
        data["file"]["signature_identifier"] = clean(
            process.file.signature_identifier, 512, "signature"
        )
    if process.file.signature_team_id is not None:
        data["file"]["signature_team_id"] = clean(
            process.file.signature_team_id, 512, "signature"
        )
    data["file"]["signature_authorities"] = [
        clean(value, 512, "signature") for value in process.file.signature_authorities
    ]
    for parent in data["ancestors"]:
        parent["name"] = clean(parent["name"], 512, "ancestry")
        if parent["executable"] is not None:
            parent["executable"] = clean(parent["executable"], 8192, "ancestry")
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
    return snapshot.model_copy(update={
        "host": host,
        "processes": [sanitize_process(p, include_command_line) for p in snapshot.processes],
    })


def terminal_text(text: str) -> str:
    """Escape ALL line/control/format characters so evidence cannot forge terminal rows."""
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char) in {"Cc", "Cf", "Cs", "Zl", "Zp"} else char
        for char in text
    )
