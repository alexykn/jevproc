"""Text and JSON presentation for corpus experiments; no transport or accounting."""

import json
from typing import Any, TextIO

from jevproc.cli.render import Terminal
from jevproc.core.corpus import CorpusCase
from jevproc.core.experiments import CorpusExperiment
from jevproc.core.models import Assessment, Report


def _answer_summary(assessment: Assessment) -> str:
    parts = []
    for rule in assessment.rules:
        answer = rule.answer
        if answer.get("type") == "noul":
            value = f"{rule.rule}=noul:{answer['noul']:.3f}"
        elif answer.get("type") == "choice":
            value = f"{rule.rule}={answer['choice']}"
        elif answer.get("type") == "score":
            value = f"{rule.rule}=score:{answer['score']:.3f}"
        else:
            value = f"{rule.rule}={rule.status}"
        parts.append(value)
    return " ".join(parts)


def _fmt_stats(stats: dict[str, Any]) -> str:
    if not stats.get("n"):
        return "n=0"
    return (
        f"n={stats['n']} mean={stats['mean']:.3f} stdev={stats['stdev']:.3f} "
        f"min={stats['min']:.3f} p10={stats['p10']:.3f} p50={stats['median']:.3f} "
        f"p90={stats['p90']:.3f} p95={stats['p95']:.3f} max={stats['max']:.3f}"
    )


def _fmt_pair(name: str, pair: dict[str, float]) -> str:
    return (
        f"{name:<22} uncertain={pair['uncertain_at']:.3f} warning={pair['warning_at']:.3f}  "
        f"macro={pair['macro_recall']:.1%} exact={pair['exact_accuracy']:.1%}  "
        f"benign-surfaced={pair['benign_surface_rate']:.1%} "
        f"benign-hard-warning={pair['benign_hard_warning_rate']:.1%}  "
        f"suspicious-surfaced={pair['suspicious_surface_recall']:.1%} "
        f"suspicious-hard-warning={pair['suspicious_warning_recall']:.1%}  "
        f"ambiguous-band={pair['ambiguous_band_recall']:.1%}"
    )


_PAIR_ORDER = ("current", "warnings_first", "balanced", "zero_benign_fp", "high_suspicious_recall")


def render_case_list(cases: list[CorpusCase], stream: TextIO, format_name: str) -> None:
    rows = [
        {key: getattr(case, key) for key in ("id", "label", "tier", "tags", "expected_statuses", "description")}
        for case in cases
    ]
    if format_name == "json":
        stream.write(json.dumps(rows, indent=2) + "\n")
        return
    # Keep the established --list contract: both text and jsonl select TSV listings.
    for row in rows:
        expected, tags = "|".join(row["expected_statuses"]), ",".join(row["tags"])
        stream.write(
            f"{row['id']}\tlabel={row['label']}\ttier={row['tier']}\t"
            f"expected={expected}\ttags={tags}\t{row['description']}\n"
        )


class CorpusReporter:
    def __init__(
        self,
        stream: TextIO,
        *,
        model: str,
        cases: int,
        runs: int,
        calibrating: bool,
        format_name: str = "text",
        color: str = "auto",
    ):
        self.stream = stream
        self.term = Terminal(stream, color=color)
        self.model, self.cases, self.runs = model, cases, runs
        self.calibrating, self.format_name = calibrating, format_name

    def _event(self, event: dict[str, Any]) -> None:
        self.stream.write(json.dumps(event, separators=(",", ":")) + "\n")
        self.stream.flush()

    def start(self) -> None:
        if self.format_name == "jsonl":
            self._event({
                "event": "start",
                "schema_version": 2,
                "model": self.model,
                "cases": self.cases,
                "runs": self.runs,
                "calibrate": self.calibrating,
            })
        elif self.format_name == "text":
            mode = "calibration" if self.calibrating else "regression"
            self.term.line(
                f"jevproc-test  {mode}  model={self.model}  cases={self.cases}  runs={self.runs}", style="\x1b[1;36m"
            )
            self.term.line(
                "Synthetic metadata only; no corpus executable, payload, or network target is run.", style="\x1b[2m"
            )
            if self.calibrating:
                self.term.line(
                    "Calibration uses raw JPR001 Noul scores; candidate thresholds are never applied automatically.",
                    style="\x1b[2m",
                )
            self.stream.flush()

    def sample(self, payload: dict[str, Any], assessment: Assessment) -> None:
        if self.format_name == "jsonl":
            self._event({"event": "sample", **payload})
        elif self.format_name == "text" and not self.calibrating:
            self._sample_text(payload, assessment)

    def _sample_text(self, payload: dict[str, Any], assessment: Assessment) -> None:
        marker, style = ("PASS", "\x1b[32m") if payload["passed"] else ("FAIL", "\x1b[31m")
        expected = "|".join(payload["expected_statuses"])
        detail = _answer_summary(assessment)
        self.term.line(
            f"{marker:<4} run={payload['run']}  {payload['id']}  label={payload['label']}  "
            f"expected={expected}  got={assessment.status}" + (f"  {detail}" if detail else ""),
            style=style,
        )
        if assessment.error:
            self.term.line(f"error: {assessment.error}", indent=6, style="\x1b[31m")
        self.stream.flush()

    def run_finished(self, run: int, report: Report, scored: int) -> None:
        if self.format_name != "text" or not self.calibrating:
            return
        summary = report.summary
        failures = summary["failed_processes"]
        self.term.line(
            f"run {run}/{self.runs}: scored={scored}/{self.cases}  failures={failures}  "
            f"requests={summary['requests']}  input={summary['input_tokens']}  "
            f"elapsed={summary['elapsed_seconds']:.2f}s",
            style="\x1b[2m" if not failures else "\x1b[31m",
        )
        self.stream.flush()

    def finish(self, experiment: CorpusExperiment, calibration: dict[str, Any] | None) -> None:
        summary = experiment.summary
        if self.format_name == "json":
            document = {
                "schema_version": 2,
                "model": self.model,
                "results": experiment.ordered_results,
                "summary": summary,
            }
            if calibration is not None:
                document["calibration"] = calibration
            self.stream.write(json.dumps(document, indent=2) + "\n")
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
    term.line("Raw JPR001 Noul distributions", style="\x1b[1m")
    for label in ("benign", "ambiguous", "suspicious", "unknown"):
        term.line(f"{label:<11} {_fmt_stats(calibration['distributions'][label])}", indent=2)


def _render_separation(term: Terminal, separation: dict[str, Any]) -> None:
    term.line()
    term.line("Separation", style="\x1b[1m")
    term.line(
        f"sample max benign={separation['max_benign_sample']:.3f}  "
        f"sample min ambiguous={separation['min_ambiguous_sample']:.3f}  "
        f"sample min suspicious={separation['min_suspicious_sample']:.3f}",
        indent=2,
    )
    term.line(
        f"sample benign→ambiguous gap={separation['benign_to_ambiguous_sample_gap']:+.3f}  "
        f"sample benign→suspicious gap={separation['benign_to_suspicious_sample_gap']:+.3f}",
        indent=2,
    )
    term.line("case means:", indent=2, style="\x1b[2m")
    term.line(
        f"max benign={separation['max_benign_mean']:.3f}  "
        f"min ambiguous={separation['min_ambiguous_mean']:.3f}  "
        f"min suspicious={separation['min_suspicious_mean']:.3f}",
        indent=2,
    )
    term.line(
        f"benign→ambiguous gap={separation['benign_to_ambiguous_gap']:+.3f}  "
        f"benign→suspicious gap={separation['benign_to_suspicious_gap']:+.3f}",
        indent=2,
    )


def _render_candidates(term: Terminal, calibration: dict[str, Any]) -> None:
    tables = (
        ("Sample-level candidate threshold pairs (operational; descriptive only; NOT applied)", "candidates"),
        ("Case-mean candidate threshold pairs (stability view only)", "case_mean_candidates"),
    )
    for title, key in tables:
        term.line()
        term.line(title, style="\x1b[1m")
        for name in _PAIR_ORDER:
            term.line(_fmt_pair(name, calibration[key][name]), indent=2)


def _render_stability(term: Terminal, calibration: dict[str, Any]) -> None:
    term.line()
    term.line("Most variable cases across runs", style="\x1b[1m")
    for item in calibration["most_unstable"][:8]:
        term.line(
            f"{item['id']:<38} label={item['label']:<10} mean={item['mean']:.3f} "
            f"stdev={item['stdev']:.3f} range={item['min']:.3f}–{item['max']:.3f}",
            indent=2,
        )
    term.line(calibration["note"], style="\x1b[2m")


def _render_calibration(term: Terminal, calibration: dict[str, Any], summary: dict[str, Any]) -> None:
    _render_distributions(term, calibration)
    _render_separation(term, calibration["separation"])
    _render_candidates(term, calibration)
    _render_stability(term, calibration)
    term.line()
    term.line(
        f"calibration: cases={summary['cases']} runs={summary['runs']} samples={summary['samples']} "
        f"failures={summary['operational_failures']} requests={summary['requests']} "
        f"input-tokens={summary['input_tokens']} elapsed={summary['elapsed_seconds']:.2f}s",
        style="\x1b[1m",
    )


def _render_regression_summary(term: Terminal, summary: dict[str, Any]) -> None:
    term.line()
    failures, mismatches = summary["operational_failures"], summary["mismatches"]
    style = "\x1b[32m" if not mismatches and not failures else "\x1b[31m"
    term.line(
        f"corpus: {summary['passed_samples']}/{summary['samples']} samples passed  "
        f"mismatches={mismatches}  failures={failures}  requests={summary['requests']}  "
        f"input-tokens={summary['input_tokens']}  elapsed={summary['elapsed_seconds']:.2f}s",
        style="\x1b[1m" + style,
    )
