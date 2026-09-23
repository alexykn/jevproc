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
        self.color = (
            "NO_COLOR" not in os.environ
            and color != "never"
            and os.getenv("TERM") != "dumb"
            and (color == "always" or stream.isatty())
        )

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

    def _process_header(self, result: Assessment) -> None:
        process = result.process
        suffix = "  [cached]" if result.cached else ""
        uid = process.uid if process.uid is not None else "?"
        self.term.line()
        self.term.line(
            f"{process.name}  PID {process.pid}  UID {uid}{suffix}",
            style="\x1b[1m",
            indent=2,
            following=4,
        )
        self.term.line(process.executable or "<executable unavailable>", indent=4, style="\x1b[2m")
        if process.ancestors:
            chain = " -> ".join(f"{parent.name} ({parent.pid})" for parent in reversed(process.ancestors))
            self.term.line(f"Parents: {chain}", indent=4, style="\x1b[2m")

    def _process_rules(self, result: Assessment) -> None:
        visible_rules = result.rules if self.verbose else [rule for rule in result.rules if rule.status in VISIBLE]
        for rule in visible_rules:
            self.term.line(
                f"{_MARKERS[rule.status]} {rule.rule}  {rule.title}",
                indent=6,
                following=8,
                style=_STYLES[rule.status],
            )
            self.term.line(_value(rule), indent=8, style=_STYLES[rule.status])
            if rule.message:
                self.term.line(rule.message, indent=8, style="\x1b[2m")

    def _process_observations(self, process: Process) -> None:
        for observation in process.observations:
            self.term.line(f"Observed: {observation}", indent=6, style="\x1b[2m")

    @staticmethod
    def _disk_details(process: Process) -> list[str]:
        candidates = (
            process.file.mode is not None and f"mode={process.file.mode:04o}",
            process.file.owner_uid is not None and f"owner-uid={process.file.owner_uid}",
            process.file.signature != "not_requested" and f"signature={process.file.signature}",
            process.file.signature_issue and f"signature-issue={process.file.signature_issue}",
            process.file.signature_identifier and f"identifier={process.file.signature_identifier}",
            process.file.signature_team_id and f"team-id={process.file.signature_team_id}",
        )
        return [str(value) for value in candidates if value]

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
