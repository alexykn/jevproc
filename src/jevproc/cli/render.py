"""Progressive plain-ANSI reporting with complete JSON output. No terminal UI framework."""

import json
import os
import shlex
import shutil
import time
from datetime import UTC, datetime
from typing import TextIO

from wcwidth import wcwidth

from jevproc import __version__
from jevproc.core.assessment import VISIBLE
from jevproc.core.models import Assessment, Process, Report, RuleResult
from jevproc.core.privacy import terminal_text

_STYLES = {
    "warning": "\x1b[33m",
    "uncertain_warning": "\x1b[36m",
    "probably_legitimate": "\x1b[32m",
    "no_warning": "\x1b[2m",
    "unknown": "\x1b[36m",
    "not_evaluated": "\x1b[2m",
    "not_applicable": "\x1b[2m",
}
_MARKERS = {
    "warning": "!",
    "uncertain_warning": "?",
    "probably_legitimate": "+",
    "no_warning": ".",
    "unknown": "?",
    "not_evaluated": "-",
    "not_applicable": "-",
}


def _wrap_cut(text: str, width: int) -> tuple[str, str]:
    cells = cut = last_space = 0
    for index, char in enumerate(text):
        cells += max(0, wcwidth(char))
        if cells > width:
            break
        cut = index + 1
        if char == " ":
            last_space = cut
    else:
        return text, ""
    cut = max(1, last_space or cut)
    return text[:cut].rstrip(), text[cut:].lstrip()


def wrap_cells(text: str, width: int) -> list[str]:
    """Wrap long paths too; codepoints are measured in terminal cells, not len()."""
    lines: list[str] = []
    remaining = text
    while remaining:
        line, remaining = _wrap_cut(remaining, width)
        lines.append(line)
    return lines or [""]


def _color_enabled(stream: TextIO, color: str) -> bool:
    conditions = (
        "NO_COLOR" not in os.environ,
        color != "never",
        os.getenv("TERM") != "dumb",
        any((color == "always", stream.isatty())),
    )
    return all(conditions)

class Terminal:
    def __init__(self, stream: TextIO, *, width: int | None = None, color: str = "auto"):
        self.stream = stream
        self.width = max(20, width or shutil.get_terminal_size(fallback=(100, 24)).columns)
        self.color = _color_enabled(stream, color)

    def _styled(self, text: str, style: str) -> str:
        return style + text + "\x1b[0m" if self.color and style else text

    @staticmethod
    def _indent(number: int, first: int, continuation: int) -> str:
        return " " * (first if number == 0 else continuation)

    def line(
        self,
        text: str = "",
        *,
        indent: int = 0,
        style: str = "",
        following: int | None = None,
    ) -> None:
        text = terminal_text(text)
        indent = min(indent, self.width // 3)
        continuation = min(following if following is not None else indent, self.width // 3)
        chunks = wrap_cells(text, self.width - max(indent, continuation))
        for number, chunk in enumerate(chunks):
            self.stream.write(self._indent(number, indent, continuation) + self._styled(chunk, style) + "\n")


def _noul_value(result: RuleResult) -> str:
    return f"noul={result.answer['noul']:.3f}"


def _choice_value(result: RuleResult) -> str:
    answer = result.answer
    return f"{answer['choice']}  p={result.probability:.3f}  conf={answer['confidence']:.3f}"


def _score_value(result: RuleResult) -> str:
    answer = result.answer
    scale = len(answer["probabilities"]) - 1
    return f"score={answer['score']:.3f}/{scale}  conf={answer['confidence']:.3f}"


_VALUE_FORMATTERS = {
    "noul": _noul_value,
    "choice": _choice_value,
    "score": _score_value,
}
_VALUE_SUFFIXES = {
    "uncertain_warning": "  [uncertain warning]",
    "unknown": "  [unknown]",
}


def _value(result: RuleResult) -> str:
    answer_type = result.answer.get("type")
    formatter = _VALUE_FORMATTERS.get(answer_type)
    text = formatter(result) if formatter is not None else result.status.replace("_", " ")
    suffix = _VALUE_SUFFIXES.get(result.status, "") if result.answer or result.status == "uncertain_warning" else ""
    return text + suffix

class Reporter:
    """Flush process results as workers complete; only the summary waits for the full scan."""

    def __init__(
        self,
        stream: TextIO,
        *,
        mode: str,
        snapshot_time: float,
        model_requested: str,
        synthetic: bool,
        total_processes: int,
        verbose: bool = False,
        format_name: str = "text",
        width: int | None = None,
        color: str = "auto",
    ) -> None:
        if format_name not in {"text", "jsonl"}:
            raise ValueError("progressive Reporter supports text and jsonl output")
        self.stream = stream
        self.mode = mode
        self.snapshot_time = snapshot_time
        self.model_requested = model_requested
        self.synthetic = synthetic
        self.total_processes = total_processes
        self.verbose = verbose
        self.format_name = format_name
        self.term = Terminal(stream, width=width, color=color)
        self.completed = 0
        self.shown = 0
        self.progress_width = 0
        self.started = time.monotonic()
        self.closed = False

        if self.format_name == "jsonl":
            self._json_line({
                "event": "start",
                "schema_version": 1,
                "mode": mode,
                "snapshot_time": snapshot_time,
                "model_requested": model_requested,
            })
        else:
            self._header()

    def _header(self) -> None:
        self.term.line(
            f"jevproc {__version__}  {self.mode}  model={self.model_requested}",
            style="\x1b[1;36m",
        )
        if self.synthetic:
            self.term.line(
                "DEMO / SYNTHETIC DATA - fixture answers, not a scan of your machine.",
                style="\x1b[1;33m",
            )
        stamp = datetime.fromtimestamp(self.snapshot_time, UTC).isoformat(timespec="seconds")
        self.term.line(
            f"Snapshot: {stamp} | read-only process triage, not a safety guarantee",
            style="\x1b[2m",
        )
        if self.verbose:
            self.term.line(
                "! warning  ? uncertain warning / unknown  + probably legitimate  . no warning  - not evaluated",
                style="\x1b[2m",
            )
        self.stream.flush()

    def _json_line(self, event: dict) -> None:
        self.stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.stream.flush()

    def _clear_progress(self) -> None:
        if not self.progress_width:
            return
        self.stream.write("\r" + (" " * self.progress_width) + "\r")
        self.progress_width = 0

    def _progress(self) -> None:
        if self.format_name != "text" or not self.stream.isatty() or self.completed >= self.total_processes:
            return
        text = terminal_text(
            f"working — completed={self.completed}/{self.total_processes} "
            f"elapsed={time.monotonic() - self.started:.1f}s"
        )
        width = max(self.progress_width, len(text))
        self.stream.write("\r" + text.ljust(width))
        self.stream.flush()
        self.progress_width = width

    def emit(self, result: Assessment) -> None:
        if self.closed:
            return
        self.completed += 1
        if self.format_name == "jsonl":
            self._json_line({"event": "process", **result.model_dump(mode="json")})
            return

        self._clear_progress()
        if self.verbose or result.status in VISIBLE:
            self.shown += 1
            self._process(result)
            self.stream.flush()
        self._progress()

    @staticmethod
    def _process_title(result: Assessment) -> str:
        process = result.process
        suffix = "  [cached]" if result.cached else ""
        uid = process.uid if process.uid is not None else "?"
        return f"{process.name}  PID {process.pid}  UID {uid}{suffix}"

    @staticmethod
    def _parents(process: Process) -> str | None:
        if not process.ancestors:
            return None
        chain = " -> ".join(f"{parent.name} ({parent.pid})" for parent in reversed(process.ancestors))
        return f"Parents: {chain}"

    def _process_header(self, result: Assessment) -> None:
        process = result.process
        self.term.line()
        self.term.line(self._process_title(result), style="\x1b[1m", indent=2, following=4)
        self.term.line(process.executable or "<executable unavailable>", indent=4, style="\x1b[2m")
        parents = self._parents(process)
        if parents is not None:
            self.term.line(parents, indent=4, style="\x1b[2m")

    def _rules_to_render(self, result: Assessment) -> list[RuleResult]:
        return result.rules if self.verbose else [rule for rule in result.rules if rule.status in VISIBLE]

    def _render_rule(self, rule: RuleResult) -> None:
        self.term.line(
            f"{_MARKERS[rule.status]} {rule.rule}  {rule.title}",
            indent=6,
            following=8,
            style=_STYLES[rule.status],
        )
        self.term.line(_value(rule), indent=8, style=_STYLES[rule.status])
        if rule.message:
            self.term.line(rule.message, indent=8, style="\x1b[2m")

    def _process_rules(self, result: Assessment) -> None:
        for rule in self._rules_to_render(result):
            self._render_rule(rule)

    def _process_observations(self, process: Process) -> None:
        for observation in process.observations:
            self.term.line(f"Observed: {observation}", indent=6, style="\x1b[2m")

    @staticmethod
    def _mode_detail(process: Process) -> str | None:
        return f"mode={process.file.mode:04o}" if process.file.mode is not None else None

    @staticmethod
    def _owner_detail(process: Process) -> str | None:
        return f"owner-uid={process.file.owner_uid}" if process.file.owner_uid is not None else None

    @staticmethod
    def _signature_detail(process: Process) -> str | None:
        return f"signature={process.file.signature}" if process.file.signature != "not_requested" else None

    @staticmethod
    def _signature_issue_detail(process: Process) -> str | None:
        return f"signature-issue={process.file.signature_issue}" if process.file.signature_issue else None

    @staticmethod
    def _identifier_detail(process: Process) -> str | None:
        return f"identifier={process.file.signature_identifier}" if process.file.signature_identifier else None

    @staticmethod
    def _team_detail(process: Process) -> str | None:
        return f"team-id={process.file.signature_team_id}" if process.file.signature_team_id else None

    @classmethod
    def _disk_details(cls, process: Process) -> list[str]:
        builders = (
            cls._mode_detail,
            cls._owner_detail,
            cls._signature_detail,
            cls._signature_issue_detail,
            cls._identifier_detail,
            cls._team_detail,
        )
        return list(filter(None, (builder(process) for builder in builders)))

    def _verbose_file(self, process: Process) -> None:
        details = self._disk_details(process)
        if details:
            self.term.line("On disk: " + "  ".join(details), indent=6, style="\x1b[2m")
        if process.file.signature_authorities:
            self.term.line(
                "Signing authority: " + " -> ".join(process.file.signature_authorities),
                indent=6,
                style="\x1b[2m",
            )
        if process.file.sha256:
            self.term.line("SHA-256 (on disk): " + process.file.sha256, indent=6, style="\x1b[2m")

    def _verbose_connections(self, process: Process) -> None:
        for connection in process.connections:
            local = f"[{connection.local_address}]:{connection.local_port}"
            remote = f"[{connection.remote_address}]:{connection.remote_port}" if connection.remote_address else "-"
            self.term.line(
                f"Socket: {connection.protocol} local={local} remote={remote} {connection.status}",
                indent=6,
                style="\x1b[2m",
            )

    def _verbose_coverage(self, process: Process) -> None:
        limited = ((key, value) for key, value in sorted(process.coverage.items()) if value != "observed")
        coverage = ", ".join(f"{key}={value}" for key, value in limited)
        if coverage:
            self.term.line(f"Coverage: {coverage}", indent=6, style="\x1b[2m")

    def _verbose_process(self, process: Process) -> None:
        if process.command_line is not None:
            self.term.line("Arguments: " + shlex.join(process.command_line), indent=6, style="\x1b[2m")
        self._verbose_file(process)
        self._verbose_connections(process)
        self._verbose_coverage(process)

    def _process(self, result: Assessment) -> None:
        self._process_header(result)
        self._process_rules(result)
        self._process_observations(result.process)
        if self.verbose:
            self._verbose_process(result.process)

    def _summary_lines(self, report: Report) -> None:
        summary = report.summary
        self.term.line()
        self.term.line(
            f"Warnings: {summary['warnings']}  |  uncertain warnings: {summary['uncertain_warnings']}  (processes)",
            style="\x1b[1;33m" if summary["warnings"] else "\x1b[36m",
        )
        self.term.line(
            f"processes={summary['processes']}  evaluated={summary['evaluated']}  unknown={summary['unknown']}  "
            f"not-evaluated={summary['not_evaluated']}  hidden={summary['processes'] - self.shown}",
            style="\x1b[2m",
        )
        self.term.line(
            f"coverage-limited={summary['coverage_limited']}  changed/exited={summary['unstable_processes']}  "
            f"omitted={summary['omitted']}  failed={summary['failed_processes']}",
            style="\x1b[2m",
        )
        self.term.line(
            f"requests={summary['requests']}  retries={summary['retries']}  cached={summary['cached_processes']}  "
            f"input-tokens={summary['input_tokens']}  elapsed={summary['elapsed_seconds']:.2f}s",
            style="\x1b[2m",
        )

    def _summary_warnings(self, report: Report) -> None:
        if report.summary["incomplete"]:
            self.term.line(
                "INCOMPLETE: some selected processes were omitted or could not be evaluated.",
                style="\x1b[1;31m",
            )
        for error in sorted({assessment.error for assessment in report.assessments if assessment.error}):
            self.term.line(f"error: {error}", style="\x1b[31m")

    def _summary_footer(self, report: Report) -> None:
        if report.mode == "offline":
            self.term.line("Offline inventory: no semantic classification was performed.", style="\x1b[2m")
        if not self.verbose:
            self.term.line("Use -v/--verbose for other processes and all rule results.", style="\x1b[2m")

    def _finish_text(self, report: Report) -> None:
        self._summary_lines(report)
        self._summary_warnings(report)
        self._summary_footer(report)
        self.stream.flush()
        self.closed = True

    def finish(self, report: Report) -> None:
        if self.closed:
            return
        self._clear_progress()
        if self.format_name == "jsonl":
            self._json_line({"event": "summary", **report.summary})
            self.closed = True
            return
        self._finish_text(report)


def render(
    report: Report,
    stream: TextIO,
    *,
    verbose: bool = False,
    format_name: str = "text",
    width: int | None = None,
    color: str = "auto",
) -> None:
    """Render a completed report; live CLI paths use Reporter directly for progressive output."""
    if format_name == "json":
        stream.write(report.model_dump_json(indent=2) + "\n")
        stream.flush()
        return

    reporter = Reporter(
        stream,
        mode=report.mode,
        snapshot_time=report.snapshot_time,
        model_requested=report.model_requested,
        synthetic=report.summary["synthetic"],
        total_processes=report.summary["processes"],
        verbose=verbose,
        format_name=format_name,
        width=width,
        color=color,
    )
    for result in report.assessments:
        reporter.emit(result)
    reporter.finish(report)
