"""Extract corpus experiments into core; leave arguments and rendering in CLI."""
from _architecture_tools import add_imports, append, extract, read, replace, write


def apply():
    cli = 'src/jevproc/cli/corpus.py'
    original = read(cli)
    core = '''
"""Repeat synthetic corpus evaluations and account for samples without terminal I/O."""
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from jevproc.core.calibration import calibration_report
from jevproc.core.corpus import CorpusCase, matches
from jevproc.core.engine import Engine
from jevproc.core.models import Assessment, Report, Snapshot
from jevproc.core.protocol import JevError
'''
    core += '\n\n' + extract(original, '_noul') + '\n\n' + extract(original, '_case_payload')
    core += '''

@dataclass
class CorpusExperiment:
    """One invocation's raw samples and run reports, never persistent policy."""
    cases: list[CorpusCase]
    runs: int
    results: list[dict[str, Any]] = field(default_factory=list)
    reports: list[Report] = field(default_factory=list)
    samples: dict[str, list[float]] = field(init=False)
    _by_pid: dict[int, CorpusCase] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._by_pid = {case.process.pid: case for case in self.cases}
        self.samples = {case.id: [] for case in self.cases}

    def record(self, run: int, assessment: Assessment) -> dict[str, Any]:
        case = self._by_pid[assessment.process.pid]
        payload = _case_payload(case, assessment, run)
        self.results.append(payload)
        if payload["noul"] is not None:
            self.samples[case.id].append(payload["noul"])
        return payload

    @property
    def ordered_results(self) -> list[dict[str, Any]]:
        return sorted(self.results, key=lambda item: (item["id"], item["run"]))

    @property
    def summary(self) -> dict[str, Any]:
        mismatches = sum(not item["passed"] for item in self.results)
        return {
            "cases": len(self.cases), "runs": self.runs, "samples": len(self.results),
            "passed_samples": len(self.results) - mismatches, "mismatches": mismatches,
            "operational_failures": sum(report.summary["failed_processes"] for report in self.reports),
            **{key: sum(report.summary[key] for report in self.reports)
               for key in ("requests", "retries", "input_tokens", "elapsed_seconds")},
        }

    def calibrate(self, uncertain_at: float, warning_at: float) -> dict[str, Any] | None:
        if self.summary["operational_failures"]:
            return None
        missing = [case.id for case in self.cases if not self.samples[case.id]]
        if missing:
            raise JevError("calibration missing JPR001 Noul samples for: " + ", ".join(missing))
        return calibration_report(self.cases, self.samples,
                                  current_uncertain=uncertain_at, current_warning=warning_at)

    def exit_code(self, calibrating: bool) -> int:
        summary = self.summary
        if summary["operational_failures"]:
            return 2
        return 0 if calibrating or not summary["mismatches"] else 1


async def run_corpus(engine: Engine, snapshot: Snapshot, cases: list[CorpusCase], runs: int, *,
                     on_sample: Callable[[dict[str, Any], Assessment], None],
                     on_run: Callable[[int, Report, int], None]) -> CorpusExperiment:
    experiment = CorpusExperiment(cases, runs)
    for run in range(1, runs + 1):
        def emit(assessment: Assessment, run_number: int = run) -> None:
            on_sample(experiment.record(run_number, assessment), assessment)

        report = await engine.scan(snapshot, mode="live", on_assessment=emit)
        experiment.reports.append(report)
        scored = sum(_noul(assessment) is not None for assessment in report.assessments)
        on_run(run, report, scored)
    return experiment


def require_calibration_labels(cases: list[CorpusCase]) -> None:
    missing = {"benign", "ambiguous", "suspicious"} - {case.label for case in cases}
    if missing:
        raise ValueError("--calibrate requires at least one selected case from: " + ", ".join(sorted(missing)))
'''
    write('src/jevproc/core/experiments.py', core)

    rendering = '''
"""Text and JSON presentation for corpus experiments; no transport or accounting."""
import json
from typing import Any, TextIO

from jevproc.cli.render import Terminal
from jevproc.core.corpus import CorpusCase
from jevproc.core.experiments import CorpusExperiment
from jevproc.core.models import Assessment, Report
'''
    rendering += '\n\n' + '\n\n'.join(extract(original, name) for name in ('_answer_summary', '_fmt_stats', '_fmt_pair'))
    rendering += '''

_PAIR_ORDER = ("current", "warnings_first", "balanced", "zero_benign_fp", "high_suspicious_recall")


def render_case_list(cases: list[CorpusCase], stream: TextIO, format_name: str) -> None:
    rows = [{key: getattr(case, key) for key in ("id", "label", "tier", "tags", "expected_statuses", "description")}
            for case in cases]
    if format_name == "json":
        stream.write(json.dumps(rows, indent=2) + "\\n")
        return
    # Keep the established --list contract: both text and jsonl select TSV listings.
    for row in rows:
        expected, tags = "|".join(row["expected_statuses"]), ",".join(row["tags"])
        stream.write(f"{row['id']}\\tlabel={row['label']}\\ttier={row['tier']}\\t"
                     f"expected={expected}\\ttags={tags}\\t{row['description']}\\n")


class CorpusReporter:
    def __init__(self, stream: TextIO, *, model: str, cases: int, runs: int,
                 calibrating: bool, format_name: str = "text", color: str = "auto"):
        self.stream = stream
        self.term = Terminal(stream, color=color)
        self.model, self.cases, self.runs = model, cases, runs
        self.calibrating, self.format_name = calibrating, format_name

    def _event(self, event: dict[str, Any]) -> None:
        self.stream.write(json.dumps(event, separators=(",", ":")) + "\\n")
        self.stream.flush()

    def start(self) -> None:
        if self.format_name == "jsonl":
            self._event({"event": "start", "schema_version": 2, "model": self.model,
                         "cases": self.cases, "runs": self.runs, "calibrate": self.calibrating})
        elif self.format_name == "text":
            mode = "calibration" if self.calibrating else "regression"
            self.term.line(f"jevproc-test  {mode}  model={self.model}  cases={self.cases}  runs={self.runs}",
                           style="\\x1b[1;36m")
            self.term.line("Synthetic metadata only; no corpus executable, payload, or network target is run.",
                           style="\\x1b[2m")
            if self.calibrating:
                self.term.line("Calibration uses raw JPR001 Noul scores; candidate thresholds are never applied automatically.",
                               style="\\x1b[2m")
            self.stream.flush()

    def sample(self, payload: dict[str, Any], assessment: Assessment) -> None:
        if self.format_name == "jsonl":
            self._event({"event": "sample", **payload})
        elif self.format_name == "text" and not self.calibrating:
            self._sample_text(payload, assessment)

    def _sample_text(self, payload: dict[str, Any], assessment: Assessment) -> None:
        marker, style = ("PASS", "\\x1b[32m") if payload["passed"] else ("FAIL", "\\x1b[31m")
        expected = "|".join(payload["expected_statuses"])
        detail = _answer_summary(assessment)
        self.term.line(f"{marker:<4} run={payload['run']}  {payload['id']}  label={payload['label']}  "
                       f"expected={expected}  got={assessment.status}" + (f"  {detail}" if detail else ""), style=style)
        if assessment.error:
            self.term.line(f"error: {assessment.error}", indent=6, style="\\x1b[31m")
        self.stream.flush()

    def run_finished(self, run: int, report: Report, scored: int) -> None:
        if self.format_name != "text" or not self.calibrating:
            return
        summary = report.summary
        failures = summary["failed_processes"]
        self.term.line(f"run {run}/{self.runs}: scored={scored}/{self.cases}  failures={failures}  "
                       f"requests={summary['requests']}  input={summary['input_tokens']}  "
                       f"elapsed={summary['elapsed_seconds']:.2f}s",
                       style="\\x1b[2m" if not failures else "\\x1b[31m")
        self.stream.flush()

    def finish(self, experiment: CorpusExperiment, calibration: dict[str, Any] | None) -> None:
        summary = experiment.summary
        if self.format_name == "json":
            document = {"schema_version": 2, "model": self.model,
                        "results": experiment.ordered_results, "summary": summary}
            if calibration is not None:
                document["calibration"] = calibration
            self.stream.write(json.dumps(document, indent=2) + "\\n")
        elif self.format_name == "jsonl":
            if calibration is not None:
                self._event({"event": "calibration", **calibration})
            self._event({"event": "summary", **summary})
        elif calibration is not None:
            _render_calibration(self.term, calibration, summary)
        else:
            _render_regression_summary(self.term, summary)
        self.stream.flush()


def _render_distributions(term: Terminal, calibration: dict[str, Any]) -> None:
    term.line()
    term.line("Raw JPR001 Noul distributions", style="\\x1b[1m")
    for label in ("benign", "ambiguous", "suspicious", "unknown"):
        term.line(f"{label:<11} {_fmt_stats(calibration['distributions'][label])}", indent=2)


def _render_separation(term: Terminal, separation: dict[str, Any]) -> None:
    term.line()
    term.line("Separation", style="\\x1b[1m")
    term.line(f"sample max benign={separation['max_benign_sample']:.3f}  "
              f"sample min ambiguous={separation['min_ambiguous_sample']:.3f}  "
              f"sample min suspicious={separation['min_suspicious_sample']:.3f}", indent=2)
    term.line(f"sample benign→ambiguous gap={separation['benign_to_ambiguous_sample_gap']:+.3f}  "
              f"sample benign→suspicious gap={separation['benign_to_suspicious_sample_gap']:+.3f}", indent=2)
    term.line("case means:", indent=2, style="\\x1b[2m")
    term.line(f"max benign={separation['max_benign_mean']:.3f}  "
              f"min ambiguous={separation['min_ambiguous_mean']:.3f}  "
              f"min suspicious={separation['min_suspicious_mean']:.3f}", indent=2)
    term.line(f"benign→ambiguous gap={separation['benign_to_ambiguous_gap']:+.3f}  "
              f"benign→suspicious gap={separation['benign_to_suspicious_gap']:+.3f}", indent=2)


def _render_candidates(term: Terminal, calibration: dict[str, Any]) -> None:
    tables = (
        ("Sample-level candidate threshold pairs (operational; descriptive only; NOT applied)", "candidates"),
        ("Case-mean candidate threshold pairs (stability view only)", "case_mean_candidates"),
    )
    for title, key in tables:
        term.line()
        term.line(title, style="\\x1b[1m")
        for name in _PAIR_ORDER:
            term.line(_fmt_pair(name, calibration[key][name]), indent=2)


def _render_stability(term: Terminal, calibration: dict[str, Any]) -> None:
    term.line()
    term.line("Most variable cases across runs", style="\\x1b[1m")
    for item in calibration["most_unstable"][:8]:
        term.line(f"{item['id']:<38} label={item['label']:<10} mean={item['mean']:.3f} "
                  f"stdev={item['stdev']:.3f} range={item['min']:.3f}–{item['max']:.3f}", indent=2)
    term.line(calibration["note"], style="\\x1b[2m")


def _render_calibration(term: Terminal, calibration: dict[str, Any], summary: dict[str, Any]) -> None:
    _render_distributions(term, calibration)
    _render_separation(term, calibration["separation"])
    _render_candidates(term, calibration)
    _render_stability(term, calibration)
    term.line()
    term.line(f"calibration: cases={summary['cases']} runs={summary['runs']} samples={summary['samples']} "
              f"failures={summary['operational_failures']} requests={summary['requests']} "
              f"input-tokens={summary['input_tokens']} elapsed={summary['elapsed_seconds']:.2f}s", style="\\x1b[1m")


def _render_regression_summary(term: Terminal, summary: dict[str, Any]) -> None:
    term.line()
    failures, mismatches = summary["operational_failures"], summary["mismatches"]
    style = "\\x1b[32m" if not mismatches and not failures else "\\x1b[31m"
    term.line(f"corpus: {summary['passed_samples']}/{summary['samples']} samples passed  "
              f"mismatches={mismatches}  failures={failures}  requests={summary['requests']}  "
              f"input-tokens={summary['input_tokens']}  elapsed={summary['elapsed_seconds']:.2f}s", style="\\x1b[1m" + style)
'''
    # Rendering templates are code strings: reduce one escaping layer while leaving
    # ordinary source strings, not literal backslash-n output, in the new module.
    rendering = rendering.replace('\\\\n', '\\n').replace('\\\\t', '\\t').replace('\\\\x1b', '\\x1b')
    write('src/jevproc/cli/corpus_render.py', rendering)

    # Retain the established CLI and exception handling; move only its responsibilities.
    keep = ['positive_int', 'parser', '_settings', '_selected', '_policy', 'main']
    header = '''
"""Arguments and application composition for synthetic corpus checks."""
import argparse
import asyncio
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from jevproc import __version__
from jevproc.cli.render import Terminal
from jevproc.cli.corpus_render import CorpusReporter, render_case_list
from jevproc.core.client import JevClient
from jevproc.core.config import Config, ConfigError, NoulQuestion, load_config
from jevproc.core.corpus import Corpus, CorpusCase, load_corpus, selected_cases, snapshot_for
from jevproc.core.engine import Engine
from jevproc.core.experiments import require_calibration_labels, run_corpus
from jevproc.core.protocol import JevError
'''
    write(cli, header + '\n\n' + '\n\n'.join(extract(original, name) for name in keep))
    replace(cli, '_selected', '''
def _selected(args: argparse.Namespace, corpus: Corpus) -> list[CorpusCase]:
    cases = selected_cases(corpus, args.case)
    if args.label:
        labels = set(args.label)
        cases = [case for case in cases if case.label in labels]
    if not cases:
        raise ValueError("corpus selection is empty")
    return cases
''')
    append(cli, '''
async def _run(args: argparse.Namespace) -> int:
    corpus = load_corpus()
    cases = _selected(args, corpus)
    if args.list:
        render_case_list(cases, sys.stdout, args.format)
        return 0
    config = _settings(args)
    uncertain, warning = _policy(config)
    if args.calibrate:
        require_calibration_labels(cases)
    runs = args.runs or (3 if args.calibrate else 1)
    reporter = CorpusReporter(sys.stdout, model=config.jev.model, cases=len(cases), runs=runs,
                              calibrating=args.calibrate, format_name=args.format, color=args.color)
    reporter.start()
    api_key = os.environ.get("TYPESAFE_API_KEY", "")
    origin = os.environ.get("TYPESAFE_BASE_URL", "https://api.typesafe.ai")
    async with JevClient(config.jev, api_key, base_url=origin) as client:
        experiment = await run_corpus(Engine(config, client), snapshot_for(corpus, cases), cases, runs,
                                      on_sample=reporter.sample, on_run=reporter.run_finished)
    calibration = experiment.calibrate(uncertain, warning) if args.calibrate else None
    reporter.finish(experiment, calibration)
    return experiment.exit_code(args.calibrate)


if __name__ == "__main__":
    raise SystemExit(main())
''')
