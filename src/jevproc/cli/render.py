"""Plain ANSI, hanging indentation and full JSON reports. No terminal UI framework."""

import json
import os
import shutil
import shlex
from datetime import UTC, datetime
from typing import TextIO

from wcwidth import wcwidth

from jevproc import __version__
from jevproc.core.assessment import VISIBLE
from jevproc.core.models import Report, RuleResult
from jevproc.core.privacy import terminal_text

_STYLES = {"warning": "\x1b[33m", "uncertain_warning": "\x1b[36m", "probably_legitimate": "\x1b[32m",
           "no_warning": "\x1b[2m", "unknown": "\x1b[36m", "not_evaluated": "\x1b[2m", "not_applicable": "\x1b[2m"}
_MARKERS = {"warning": "!", "uncertain_warning": "?", "probably_legitimate": "+", "no_warning": ".",
            "unknown": "?", "not_evaluated": "-", "not_applicable": "-"}


def wrap_cells(text: str, width: int) -> list[str]:
    """Wrap long paths too; codepoints are measured in terminal cells, not len()."""
    lines = []
    remaining = text
    while remaining:
        cells, cut, last_space = 0, 0, 0
        for index, char in enumerate(remaining):
            cells += max(0, wcwidth(char))
            if cells > width:
                break
            cut = index + 1
            if char == " ":
                last_space = cut
        else:
            lines.append(remaining)
            break
        if last_space:
            cut = last_space
        cut = max(1, cut)
        lines.append(remaining[:cut].rstrip())
        remaining = remaining[cut:].lstrip()
    return lines or [""]


class Terminal:
    def __init__(self, stream: TextIO, *, width: int | None = None, color: str = "auto"):
        self.stream = stream
        self.width = max(20, width or shutil.get_terminal_size(fallback=(100, 24)).columns)
        self.color = ("NO_COLOR" not in os.environ and color != "never" and os.getenv("TERM") != "dumb"
                      and (color == "always" or stream.isatty()))

    def line(self, text: str = "", *, indent: int = 0, style: str = "", following: int | None = None) -> None:
        text = terminal_text(text)
        indent = min(indent, self.width // 3)
        continuation = min(following if following is not None else indent, self.width // 3)
        # Use the smaller width for both lines; never overrun a narrow terminal.
        chunks = wrap_cells(text, self.width - max(indent, continuation))
        for number, chunk in enumerate(chunks):
            prefix = " " * (indent if number == 0 else continuation)
            if self.color and style:
                chunk = style + chunk + "\x1b[0m"
            self.stream.write(prefix + chunk + "\n")


def _value(result: RuleResult) -> str:
    answer = result.answer
    if answer.get("type") == "noul":
        text = f"noul={answer['noul']:.3f}"
    elif answer.get("type") == "choice":
        text = f"{answer['choice']}  p={result.probability:.3f}  conf={answer['confidence']:.3f}"
    elif answer.get("type") == "score":
        scale = len(answer["probabilities"]) - 1
        text = f"score={answer['score']:.3f}/{scale}  conf={answer['confidence']:.3f}"
    else:
        text = result.status.replace("_", " ")
    if result.status == "uncertain_warning":
        text += "  [uncertain warning]"
    elif result.status == "unknown" and answer:
        text += "  [unknown]"
    return text


def render(report: Report, stream: TextIO, *, verbose: bool = False, format_name: str = "text",
           width: int | None = None, color: str = "auto") -> None:
    if format_name == "json":
        stream.write(report.model_dump_json(indent=2) + "\n")
        return
    if format_name == "jsonl":
        stream.write(json.dumps({"event": "start", "schema_version": 1, "mode": report.mode,
                                 "snapshot_time": report.snapshot_time, "model_requested": report.model_requested}) + "\n")
        for result in report.assessments:
            stream.write(json.dumps({"event": "process", **result.model_dump(mode="json")}) + "\n")
        stream.write(json.dumps({"event": "summary", **report.summary}) + "\n")
        return
    term = Terminal(stream, width=width, color=color)
    term.line(f"jevproc {__version__}  {report.mode}  model={report.model_requested}", style="\x1b[1;36m")
    if report.summary["synthetic"]:
        term.line("DEMO / SYNTHETIC DATA - fixture answers, not a scan of your machine.", style="\x1b[1;33m")
    stamp = datetime.fromtimestamp(report.snapshot_time, UTC).isoformat(timespec="seconds")
    term.line(f"Snapshot: {stamp} | read-only process triage, not a safety guarantee", style="\x1b[2m")
    if verbose:
        term.line("! warning  ? uncertain warning / unknown  + probably legitimate  . no warning  - not evaluated", style="\x1b[2m")
    shown = 0
    for result in report.assessments:
        if not verbose and result.status not in VISIBLE:
            continue
        shown += 1
        process = result.process
        term.line()
        suffix = "  [cached]" if result.cached else ""
        term.line(f"{process.name}  PID {process.pid}  UID {process.uid if process.uid is not None else '?'}{suffix}",
                  style="\x1b[1m", indent=2, following=4)
        term.line(process.executable or "<executable unavailable>", indent=4, style="\x1b[2m")
        if process.ancestors:
            chain = " -> ".join(f"{p.name} ({p.pid})" for p in reversed(process.ancestors))
            term.line(f"Parents: {chain}", indent=4, style="\x1b[2m")
        for rule in result.rules:
            if not verbose and rule.status not in VISIBLE:
                continue
            term.line(f"{_MARKERS[rule.status]} {rule.rule}  {rule.title}", indent=6, following=8,
                      style=_STYLES[rule.status])
            term.line(_value(rule), indent=8, style=_STYLES[rule.status])
            if rule.message:
                term.line(rule.message, indent=8, style="\x1b[2m")
        for observation in process.observations:
            term.line(f"Observed: {observation}", indent=6, style="\x1b[2m")
        if verbose:
            if process.command_line is not None:
                term.line("Arguments: " + shlex.join(process.command_line), indent=6, style="\x1b[2m")
            details = []
            if process.file.mode is not None:
                details.append(f"mode={process.file.mode:04o}")
            if process.file.owner_uid is not None:
                details.append(f"owner-uid={process.file.owner_uid}")
            if process.file.signature != "not_requested":
                details.append(f"signature={process.file.signature}")
            if details:
                term.line("On disk: " + "  ".join(details), indent=6, style="\x1b[2m")
            if process.file.sha256:
                term.line("SHA-256 (on disk): " + process.file.sha256, indent=6, style="\x1b[2m")
            for connection in process.connections:
                local = f"[{connection.local_address}]:{connection.local_port}"
                remote = f"[{connection.remote_address}]:{connection.remote_port}" if connection.remote_address else "-"
                term.line(f"Socket: {connection.protocol} local={local} remote={remote} {connection.status}",
                          indent=6, style="\x1b[2m")
            coverage = ", ".join(f"{key}={value}" for key, value in sorted(process.coverage.items()) if value != "observed")
            if coverage:
                term.line(f"Coverage: {coverage}", indent=6, style="\x1b[2m")
    summary = report.summary
    term.line()
    term.line(f"Warnings: {summary['warnings']}  |  uncertain warnings: {summary['uncertain_warnings']}  (processes)",
              style="\x1b[1;33m" if summary["warnings"] else "\x1b[36m")
    term.line(f"processes={summary['processes']}  evaluated={summary['evaluated']}  unknown={summary['unknown']}  "
              f"not-evaluated={summary['not_evaluated']}  hidden={summary['processes'] - shown}", style="\x1b[2m")
    term.line(f"coverage-limited={summary['coverage_limited']}  changed/exited={summary['unstable_processes']}  "
              f"omitted={summary['omitted']}  failed={summary['failed_processes']}", style="\x1b[2m")
    term.line(f"requests={summary['requests']}  retries={summary['retries']}  cached={summary['cached_processes']}  "
              f"input-tokens={summary['input_tokens']}  elapsed={summary['elapsed_seconds']:.2f}s", style="\x1b[2m")
    if summary["incomplete"]:
        term.line("INCOMPLETE: some selected processes were omitted or could not be evaluated.", style="\x1b[1;31m")
    for error in sorted({a.error for a in report.assessments if a.error}):
        term.line(f"error: {error}", style="\x1b[31m")
    if report.mode == "offline":
        term.line("Offline inventory: no semantic classification was performed.", style="\x1b[2m")
    if not verbose:
        term.line("Use -v/--verbose for other processes and all rule results.", style="\x1b[2m")
    stream.flush()
