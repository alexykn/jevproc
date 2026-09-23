"""Raw Noul calibration statistics for the synthetic corpus.

This module never changes policy. It reports both run-level operational metrics
and case-mean stability metrics. Operational threshold candidates are selected
from individual samples so repeated-run tails cannot be hidden by averaging.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from itertools import pairwise
from typing import Any, Iterable

from jevproc.core.corpus import CorpusCase


def quantile(values: list[float], q: float) -> float:
    if not values:
        raise ValueError("quantile requires at least one value")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def describe(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "min": min(values),
        "p05": quantile(values, 0.05),
        "p10": quantile(values, 0.10),
        "p25": quantile(values, 0.25),
        "median": quantile(values, 0.50),
        "p75": quantile(values, 0.75),
        "p90": quantile(values, 0.90),
        "p95": quantile(values, 0.95),
        "max": max(values),
        "mean": statistics.fmean(values),
        "stdev": statistics.pstdev(values) if len(values) > 1 else 0.0,
    }


def _thresholds(values: Iterable[float]) -> list[float]:
    """Include observed values as well as midpoints.

    Scores are often quantized to hundredths. An observed boundary such as 0.08
    therefore has operational meaning and must be eligible as a candidate.
    """
    unique = sorted(set(values))
    if not unique:
        return []
    candidates = {0.0, 1.0, *unique}
    candidates.update((left + right) / 2 for left, right in pairwise(unique))
    return sorted(max(0.0, min(1.0, value)) for value in candidates)


@dataclass(frozen=True)
class PairMetrics:
    uncertain_at: float
    warning_at: float
    macro_recall: float
    exact_accuracy: float
    benign_false_positive_rate: float
    benign_warning_rate: float
    benign_surface_rate: float
    benign_hard_warning_rate: float
    ambiguous_band_recall: float
    suspicious_surface_recall: float
    suspicious_warning_recall: float

    def as_dict(self) -> dict[str, float]:
        return {
            "uncertain_at": self.uncertain_at,
            "warning_at": self.warning_at,
            "macro_recall": self.macro_recall,
            "exact_accuracy": self.exact_accuracy,
            "benign_false_positive_rate": self.benign_false_positive_rate,
            "benign_warning_rate": self.benign_warning_rate,
            "benign_surface_rate": self.benign_surface_rate,
            "benign_hard_warning_rate": self.benign_hard_warning_rate,
            "ambiguous_band_recall": self.ambiguous_band_recall,
            "suspicious_surface_recall": self.suspicious_surface_recall,
            "suspicious_warning_recall": self.suspicious_warning_recall,
        }


def _rate(matches: int, total: int) -> float:
    return matches / total if total else 0.0


_CALIBRATION_LABELS = ("benign", "ambiguous", "suspicious")
_TARGET_BAND = {
    "benign": "benign",
    "ambiguous": "ambiguous",
    "suspicious": "warning",
}


def _predicted_band(score: float, uncertain_at: float, warning_at: float) -> str:
    bands = (
        (score >= warning_at, "warning"),
        (score >= uncertain_at, "ambiguous"),
    )
    return next((band for matches, band in bands if matches), "benign")


def _labelled_predictions(
    observations: Iterable[tuple[str, float]],
    uncertain_at: float,
    warning_at: float,
) -> list[tuple[str, str]]:
    labelled = [(label, score) for label, score in observations if label != "unknown"]
    unsupported = {label for label, _ in labelled}.difference(_CALIBRATION_LABELS)
    if unsupported:
        raise ValueError(f"unsupported calibration label: {min(unsupported)}")
    return [(label, _predicted_band(score, uncertain_at, warning_at)) for label, score in labelled]


def _pair_counts(predictions: list[tuple[str, str]]) -> tuple[Counter[str], Counter[tuple[str, str]]]:
    return Counter(label for label, _ in predictions), Counter(predictions)


def _evaluate_observations(
    observations: Iterable[tuple[str, float]],
    uncertain_at: float,
    warning_at: float,
) -> PairMetrics:
    if not 0 <= uncertain_at < warning_at <= 1:
        raise ValueError("candidate thresholds must satisfy 0 <= uncertain < warning <= 1")

    totals, counts = _pair_counts(_labelled_predictions(observations, uncertain_at, warning_at))
    correct = {label: counts[(label, _TARGET_BAND[label])] for label in _CALIBRATION_LABELS}
    recalls = [_rate(correct[label], totals[label]) for label in _CALIBRATION_LABELS]
    benign_fp = totals["benign"] - counts[("benign", "benign")]
    benign_warning = counts[("benign", "warning")]
    suspicious_surface = counts[("suspicious", "ambiguous")] + counts[("suspicious", "warning")]
    total = sum(totals.values())
    return PairMetrics(
        uncertain_at=uncertain_at,
        warning_at=warning_at,
        macro_recall=sum(recalls) / len(recalls),
        exact_accuracy=_rate(sum(correct.values()), total),
        benign_false_positive_rate=_rate(benign_fp, totals["benign"]),
        benign_warning_rate=_rate(benign_warning, totals["benign"]),
        benign_surface_rate=_rate(benign_fp, totals["benign"]),
        benign_hard_warning_rate=_rate(benign_warning, totals["benign"]),
        ambiguous_band_recall=_rate(correct["ambiguous"], totals["ambiguous"]),
        suspicious_surface_recall=_rate(suspicious_surface, totals["suspicious"]),
        suspicious_warning_recall=_rate(correct["suspicious"], totals["suspicious"]),
    )

def evaluate_pair(
    case_means: dict[str, float],
    cases: dict[str, CorpusCase],
    uncertain_at: float,
    warning_at: float,
) -> PairMetrics:
    """Evaluate one score per case.

    Kept for case-mean stability analysis and backwards-compatible callers.
    Operational calibration should use evaluate_samples().
    """
    observations: list[tuple[str, float]] = [
        (cases[case_id].label, score) for case_id, score in case_means.items() if cases[case_id].label != "unknown"
    ]
    return _evaluate_observations(observations, uncertain_at, warning_at)


def evaluate_samples(
    samples: dict[str, list[float]],
    cases: dict[str, CorpusCase],
    uncertain_at: float,
    warning_at: float,
) -> PairMetrics:
    """Evaluate every repeated run independently."""
    observations: list[tuple[str, float]] = [
        (cases[case_id].label, score)
        for case_id, values in samples.items()
        for score in values
        if cases[case_id].label != "unknown"
    ]
    return _evaluate_observations(observations, uncertain_at, warning_at)


def _balanced_key(item: PairMetrics) -> tuple:
    return (
        item.macro_recall,
        item.exact_accuracy,
        -item.benign_false_positive_rate,
        item.suspicious_warning_recall,
        item.ambiguous_band_recall,
        item.uncertain_at,
        item.warning_at,
    )


def _conservative_key(item: PairMetrics) -> tuple:
    return (
        item.suspicious_warning_recall,
        item.ambiguous_band_recall,
        item.macro_recall,
        -item.warning_at,
        item.uncertain_at,
    )


def _warnings_first_key(item: PairMetrics) -> tuple:
    return (
        item.suspicious_surface_recall,
        -item.benign_surface_rate,
        item.suspicious_warning_recall,
        item.uncertain_at,
        item.ambiguous_band_recall,
        item.macro_recall,
        item.warning_at,
    )


def _recall_first_key(item: PairMetrics) -> tuple:
    return (
        item.benign_false_positive_rate,
        item.benign_warning_rate,
        -item.ambiguous_band_recall,
        -item.macro_recall,
        -item.uncertain_at,
    )


def _filtered_pairs(
    pairs: list[PairMetrics],
    predicate: Callable[[PairMetrics], bool],
) -> list[PairMetrics]:
    selected = list(filter(predicate, pairs))
    return selected or pairs


def _candidate_grid(observations: list[tuple[str, float]]) -> list[PairMetrics]:
    thresholds = _thresholds(score for _, score in observations)
    return [
        _evaluate_observations(observations, uncertain, warning)
        for uncertain in thresholds
        for warning in thresholds
        if uncertain < warning
    ]


def _candidate_pairs_from_observations(
    observations: list[tuple[str, float]],
    current_uncertain: float,
    current_warning: float,
) -> dict[str, Any]:
    pairs = _candidate_grid(observations)
    if not pairs:
        raise ValueError("not enough labelled score values to calibrate thresholds")

    balanced = max(pairs, key=_balanced_key)
    conservative = max(
        _filtered_pairs(pairs, lambda item: item.benign_false_positive_rate == 0),
        key=_conservative_key,
    )
    warnings_first = max(
        _filtered_pairs(pairs, lambda item: item.benign_hard_warning_rate == 0),
        key=_warnings_first_key,
    )
    recall_first = min(
        _filtered_pairs(pairs, lambda item: item.suspicious_warning_recall >= 0.95),
        key=_recall_first_key,
    )
    current = _evaluate_observations(observations, current_uncertain, current_warning)
    return {
        "current": current.as_dict(),
        "balanced": balanced.as_dict(),
        "zero_benign_fp": conservative.as_dict(),
        "warnings_first": warnings_first.as_dict(),
        "high_suspicious_recall": recall_first.as_dict(),
    }

def candidate_pairs(
    case_means: dict[str, float],
    cases: dict[str, CorpusCase],
    current_uncertain: float,
    current_warning: float,
) -> dict[str, Any]:
    observations: list[tuple[str, float]] = [
        (cases[case_id].label, value)
        for case_id, value in case_means.items()
        if cases[case_id].label in {"benign", "ambiguous", "suspicious"}
    ]
    return _candidate_pairs_from_observations(
        observations,
        current_uncertain=current_uncertain,
        current_warning=current_warning,
    )


def sample_candidate_pairs(
    samples: dict[str, list[float]],
    cases: dict[str, CorpusCase],
    current_uncertain: float,
    current_warning: float,
) -> dict[str, Any]:
    observations: list[tuple[str, float]] = [
        (cases[case_id].label, value)
        for case_id, values in samples.items()
        for value in values
        if cases[case_id].label in {"benign", "ambiguous", "suspicious"}
    ]
    return _candidate_pairs_from_observations(
        observations,
        current_uncertain=current_uncertain,
        current_warning=current_warning,
    )


def _case_calibration_data(
    cases: list[CorpusCase],
    samples: dict[str, list[float]],
) -> tuple[dict[str, dict[str, Any]], dict[str, list[float]], dict[str, float]]:
    case_stats: dict[str, dict[str, Any]] = {}
    label_samples: dict[str, list[float]] = {label: [] for label in (*_CALIBRATION_LABELS, "unknown")}
    case_means: dict[str, float] = {}
    for case in cases:
        values = samples.get(case.id, [])
        case_stats[case.id] = {"label": case.label, "tier": case.tier, "tags": case.tags, **describe(values)}
        if values:
            label_samples[case.label].extend(values)
            case_means[case.id] = statistics.fmean(values)
    return case_stats, label_samples, case_means


def _label_means(
    cases: list[CorpusCase],
    case_means: dict[str, float],
) -> dict[str, list[float]]:
    result = {label: [] for label in _CALIBRATION_LABELS}
    for case in cases:
        if case.id in case_means and case.label in result:
            result[case.label].append(case_means[case.id])
    return result


def _maximum(values: list[float]) -> float | None:
    return max(values) if values else None


def _minimum(values: list[float]) -> float | None:
    return min(values) if values else None


def _gap(lower: list[float], upper: list[float]) -> float | None:
    return min(upper) - max(lower) if lower and upper else None


def _separation(
    means: dict[str, list[float]],
    samples: dict[str, list[float]],
) -> dict[str, float | None]:
    benign_means = means["benign"]
    ambiguous_means = means["ambiguous"]
    suspicious_means = means["suspicious"]
    benign_samples = samples["benign"]
    ambiguous_samples = samples["ambiguous"]
    suspicious_samples = samples["suspicious"]
    return {
        "max_benign_mean": _maximum(benign_means),
        "min_ambiguous_mean": _minimum(ambiguous_means),
        "min_suspicious_mean": _minimum(suspicious_means),
        "benign_to_ambiguous_gap": _gap(benign_means, ambiguous_means),
        "benign_to_suspicious_gap": _gap(benign_means, suspicious_means),
        "max_benign_sample": _maximum(benign_samples),
        "min_ambiguous_sample": _minimum(ambiguous_samples),
        "min_suspicious_sample": _minimum(suspicious_samples),
        "benign_to_ambiguous_sample_gap": _gap(benign_samples, ambiguous_samples),
        "benign_to_suspicious_sample_gap": _gap(benign_samples, suspicious_samples),
    }


def _unstable_case(case: CorpusCase, stats: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": case.id,
        "label": case.label,
        "mean": stats.get("mean"),
        "stdev": stats.get("stdev"),
        "min": stats.get("min"),
        "max": stats.get("max"),
        "span": stats["max"] - stats["min"],
    }


def _unstable_cases(cases: list[CorpusCase], case_stats: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    observed = (case for case in cases if case_stats[case.id].get("n", 0))
    rows = [_unstable_case(case, case_stats[case.id]) for case in observed]
    return sorted(rows, key=lambda item: item["span"], reverse=True)


def calibration_report(
    cases: list[CorpusCase],
    samples: dict[str, list[float]],
    *,
    current_uncertain: float,
    current_warning: float,
) -> dict[str, Any]:
    case_map = {case.id: case for case in cases}
    case_stats, label_samples, case_means = _case_calibration_data(cases, samples)
    candidates = sample_candidate_pairs(samples, case_map, current_uncertain, current_warning)
    case_mean_candidates = candidate_pairs(case_means, case_map, current_uncertain, current_warning)
    return {
        "distributions": {label: describe(values) for label, values in label_samples.items()},
        "cases": case_stats,
        "separation": _separation(_label_means(cases, case_means), label_samples),
        "candidates": candidates,
        "case_mean_candidates": case_mean_candidates,
        "candidate_basis": "individual_samples",
        "most_unstable": _unstable_cases(cases, case_stats)[:10],
        "note": (
            "Operational candidate thresholds use individual repeated-run samples. "
            "Case-mean candidates are retained only as a stability view. "
            "All candidates are descriptive synthetic-corpus operating points and are never applied automatically."
        ),
    }

