"""Raw Noul calibration statistics for the synthetic corpus.

This module never changes policy. It reports both run-level operational metrics
and case-mean stability metrics. Operational threshold candidates are selected
from individual samples so repeated-run tails cannot be hidden by averaging.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
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
    candidates.update((left + right) / 2 for left, right in zip(unique, unique[1:]))
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


def _evaluate_observations(
    observations: Iterable[tuple[str, float]],
    uncertain_at: float,
    warning_at: float,
) -> PairMetrics:
    if not 0 <= uncertain_at < warning_at <= 1:
        raise ValueError("candidate thresholds must satisfy 0 <= uncertain < warning <= 1")

    totals = {"benign": 0, "ambiguous": 0, "suspicious": 0}
    correct = {"benign": 0, "ambiguous": 0, "suspicious": 0}
    benign_fp = benign_warning = suspicious_surface = 0

    for label, score in observations:
        if label == "unknown":
            continue
        if label not in totals:
            raise ValueError(f"unsupported calibration label: {label}")
        totals[label] += 1
        predicted = (
            "warning"
            if score >= warning_at
            else "ambiguous"
            if score >= uncertain_at
            else "benign"
        )
        target = {
            "benign": "benign",
            "ambiguous": "ambiguous",
            "suspicious": "warning",
        }[label]
        correct[label] += predicted == target
        if label == "benign":
            benign_fp += predicted != "benign"
            benign_warning += predicted == "warning"
        elif label == "suspicious":
            suspicious_surface += predicted in {"ambiguous", "warning"}

    recalls = [_rate(correct[label], totals[label]) for label in ("benign", "ambiguous", "suspicious")]
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
    observations = [
        (cases[case_id].label, score)
        for case_id, score in case_means.items()
        if cases[case_id].label != "unknown"
    ]
    return _evaluate_observations(observations, uncertain_at, warning_at)


def evaluate_samples(
    samples: dict[str, list[float]],
    cases: dict[str, CorpusCase],
    uncertain_at: float,
    warning_at: float,
) -> PairMetrics:
    """Evaluate every repeated run independently."""
    observations = [
        (cases[case_id].label, score)
        for case_id, values in samples.items()
        for score in values
        if cases[case_id].label != "unknown"
    ]
    return _evaluate_observations(observations, uncertain_at, warning_at)


def _candidate_pairs_from_observations(
    observations: list[tuple[str, float]],
    current_uncertain: float,
    current_warning: float,
) -> dict[str, Any]:
    thresholds = _thresholds(score for _, score in observations)
    pairs = [
        _evaluate_observations(observations, uncertain, warning)
        for uncertain in thresholds
        for warning in thresholds
        if uncertain < warning
    ]
    if not pairs:
        raise ValueError("not enough labelled score values to calibrate thresholds")

    balanced = max(
        pairs,
        key=lambda item: (
            item.macro_recall,
            item.exact_accuracy,
            -item.benign_false_positive_rate,
            item.suspicious_warning_recall,
            item.ambiguous_band_recall,
            item.uncertain_at,
            item.warning_at,
        ),
    )

    zero_fp = [item for item in pairs if item.benign_false_positive_rate == 0]
    conservative = max(
        zero_fp or pairs,
        key=lambda item: (
            item.suspicious_warning_recall,
            item.ambiguous_band_recall,
            item.macro_recall,
            -item.warning_at,
            item.uncertain_at,
        ),
    )

    no_hard_benign = [item for item in pairs if item.benign_hard_warning_rate == 0]
    warnings_first = max(
        no_hard_benign or pairs,
        key=lambda item: (
            item.suspicious_surface_recall,
            -item.benign_surface_rate,
            item.suspicious_warning_recall,
            item.uncertain_at,
            item.ambiguous_band_recall,
            item.macro_recall,
            item.warning_at,
        ),
    )

    high_recall = [item for item in pairs if item.suspicious_warning_recall >= 0.95]
    recall_first = min(
        high_recall or pairs,
        key=lambda item: (
            item.benign_false_positive_rate,
            item.benign_warning_rate,
            -item.ambiguous_band_recall,
            -item.macro_recall,
            -item.uncertain_at,
        ),
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
    observations = [
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
    observations = [
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


def calibration_report(
    cases: list[CorpusCase],
    samples: dict[str, list[float]],
    *,
    current_uncertain: float,
    current_warning: float,
) -> dict[str, Any]:
    case_map = {case.id: case for case in cases}
    case_stats: dict[str, dict[str, Any]] = {}
    label_samples: dict[str, list[float]] = {
        "benign": [],
        "ambiguous": [],
        "suspicious": [],
        "unknown": [],
    }
    case_means: dict[str, float] = {}

    for case in cases:
        values = samples.get(case.id, [])
        stats = describe(values)
        case_stats[case.id] = {
            "label": case.label,
            "tier": case.tier,
            "tags": case.tags,
            **stats,
        }
        if values:
            label_samples[case.label].extend(values)
            case_means[case.id] = statistics.fmean(values)

    distributions = {label: describe(values) for label, values in label_samples.items()}
    candidates = sample_candidate_pairs(
        samples,
        case_map,
        current_uncertain=current_uncertain,
        current_warning=current_warning,
    )
    case_mean_candidates = candidate_pairs(
        case_means,
        case_map,
        current_uncertain=current_uncertain,
        current_warning=current_warning,
    )

    benign_means = [case_means[c.id] for c in cases if c.label == "benign" and c.id in case_means]
    ambiguous_means = [case_means[c.id] for c in cases if c.label == "ambiguous" and c.id in case_means]
    suspicious_means = [case_means[c.id] for c in cases if c.label == "suspicious" and c.id in case_means]
    benign_samples = label_samples["benign"]
    ambiguous_samples = label_samples["ambiguous"]
    suspicious_samples = label_samples["suspicious"]

    separation = {
        "max_benign_mean": max(benign_means) if benign_means else None,
        "min_ambiguous_mean": min(ambiguous_means) if ambiguous_means else None,
        "min_suspicious_mean": min(suspicious_means) if suspicious_means else None,
        "benign_to_ambiguous_gap": (
            min(ambiguous_means) - max(benign_means)
            if benign_means and ambiguous_means
            else None
        ),
        "benign_to_suspicious_gap": (
            min(suspicious_means) - max(benign_means)
            if benign_means and suspicious_means
            else None
        ),
        "max_benign_sample": max(benign_samples) if benign_samples else None,
        "min_ambiguous_sample": min(ambiguous_samples) if ambiguous_samples else None,
        "min_suspicious_sample": min(suspicious_samples) if suspicious_samples else None,
        "benign_to_ambiguous_sample_gap": (
            min(ambiguous_samples) - max(benign_samples)
            if benign_samples and ambiguous_samples
            else None
        ),
        "benign_to_suspicious_sample_gap": (
            min(suspicious_samples) - max(benign_samples)
            if benign_samples and suspicious_samples
            else None
        ),
    }

    unstable = sorted(
        (
            {
                "id": case.id,
                "label": case.label,
                "mean": case_stats[case.id].get("mean"),
                "stdev": case_stats[case.id].get("stdev"),
                "min": case_stats[case.id].get("min"),
                "max": case_stats[case.id].get("max"),
                "span": (
                    case_stats[case.id]["max"] - case_stats[case.id]["min"]
                    if case_stats[case.id].get("n", 0)
                    else None
                ),
            }
            for case in cases
            if case_stats[case.id].get("n", 0)
        ),
        key=lambda item: item["span"] or 0,
        reverse=True,
    )

    return {
        "distributions": distributions,
        "cases": case_stats,
        "separation": separation,
        "candidates": candidates,
        "case_mean_candidates": case_mean_candidates,
        "candidate_basis": "individual_samples",
        "most_unstable": unstable[:10],
        "note": (
            "Operational candidate thresholds use individual repeated-run samples. "
            "Case-mean candidates are retained only as a stability view. "
            "All candidates are descriptive synthetic-corpus operating points and are never applied automatically."
        ),
    }
