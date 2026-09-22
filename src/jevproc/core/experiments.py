"""Repeat synthetic corpus evaluations and account for samples without terminal I/O."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from jevproc.core.calibration import calibration_report
from jevproc.core.corpus import CorpusCase, matches
from jevproc.core.engine import Engine
from jevproc.core.models import Assessment, Report, Snapshot
from jevproc.core.protocol import JevError


def _noul(assessment: Assessment) -> float | None:
    for rule in assessment.rules:
        if rule.rule == "JPR001" and rule.answer.get("type") == "noul":
            return float(rule.answer["noul"])
    return None


def _case_payload(case: CorpusCase, assessment: Assessment, run: int) -> dict[str, Any]:
    return {
        "run": run,
        "id": case.id,
        "label": case.label,
        "tier": case.tier,
        "tags": case.tags,
        "description": case.description,
        "expected_statuses": case.expected_statuses,
        "actual_status": assessment.status,
        "noul": _noul(assessment),
        "passed": matches(case, assessment.status),
        "cached": assessment.cached,
        "model": assessment.model,
        "error": assessment.error,
        "rules": [rule.model_dump(mode="json") for rule in assessment.rules],
    }


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
            "cases": len(self.cases),
            "runs": self.runs,
            "samples": len(self.results),
            "passed_samples": len(self.results) - mismatches,
            "mismatches": mismatches,
            "operational_failures": sum(report.summary["failed_processes"] for report in self.reports),
            **{
                key: sum(report.summary[key] for report in self.reports)
                for key in ("requests", "retries", "input_tokens", "elapsed_seconds")
            },
        }

    def calibrate(self, uncertain_at: float, warning_at: float) -> dict[str, Any] | None:
        if self.summary["operational_failures"]:
            return None
        missing = [case.id for case in self.cases if not self.samples[case.id]]
        if missing:
            raise JevError("calibration missing JPR001 Noul samples for: " + ", ".join(missing))
        return calibration_report(self.cases, self.samples, current_uncertain=uncertain_at, current_warning=warning_at)

    def exit_code(self, calibrating: bool) -> int:
        summary = self.summary
        if summary["operational_failures"]:
            return 2
        return 0 if calibrating or not summary["mismatches"] else 1


async def run_corpus(
    engine: Engine,
    snapshot: Snapshot,
    cases: list[CorpusCase],
    runs: int,
    *,
    on_sample: Callable[[dict[str, Any], Assessment], None],
    on_run: Callable[[int, Report, int], None],
) -> CorpusExperiment:
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
