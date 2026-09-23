"""Local, testable warning policy. Model confidence is not threat severity."""

from dataclasses import dataclass

from jevproc.core.config import Policy, Rule
from jevproc.core.models import Assessment, Process, RuleResult, Status
from jevproc.core.protocol import (
    Answer,
    ChoiceAnswer,
    NoulAnswer,
    ScoreAnswer,
    applicable,
)

VISIBLE: frozenset[str] = frozenset({"warning", "uncertain_warning"})


def evidence_limited(rule: Rule, process: Process) -> bool:
    sources = rule.requires or ["executable", "name", "identity"]
    return any(process.coverage.get(source) != "observed" for source in sources)


def skipped_rule(rule: Rule, process: Process) -> RuleResult:
    missing = [s for s in rule.requires if process.coverage.get(s) not in {"observed", "partial", "truncated"}]
    if missing:
        details = ", ".join(f"{s}={process.coverage.get(s, 'unavailable')}" for s in missing)
        return RuleResult(rule=rule.id, title=rule.title, status="unknown", message=f"Not evaluated: {details}.")
    return RuleResult(
        rule=rule.id,
        title=rule.title,
        status="not_applicable",
        message="No relevant evidence items were observed; this is not proof of absence.",
    )


def judge(rule: Rule, process: Process, answer: Answer) -> RuleResult:
    limited = evidence_limited(rule, process)
    decision = _decide(rule.policy, answer, limited)
    message = rule.message if decision.status in VISIBLE else ""
    if limited and decision.status in VISIBLE:
        message += " Relevant evidence is partial or unavailable; this finding remains uncertain."
    return RuleResult(
        rule=rule.id,
        title=rule.title,
        status=decision.status,
        message=message,
        value=decision.value,
        probability=decision.probability,
        confidence=decision.confidence,
        answer=answer.model_dump(mode="json"),
    )


_AGGREGATE_PRIORITY: tuple[Status, ...] = (
    "warning",
    "uncertain_warning",
    "unknown",
    "probably_legitimate",
    "no_warning",
)


def aggregate(rules: list[RuleResult]) -> Status:
    statuses = {result.status for result in rules}
    return next((status for status in _AGGREGATE_PRIORITY if status in statuses), "not_evaluated")


def assess(process: Process, rules: list[Rule], answers: dict[str, Answer], model: str, cached: bool) -> Assessment:
    results = [
        judge(rule, process, answers[f"{process.ref}_{rule.id}"])
        if applicable(rule, process)
        else skipped_rule(rule, process)
        for rule in rules
    ]
    return Assessment(process=process, status=aggregate(results), rules=results, cached=cached, model=model)


@dataclass(frozen=True)
class _Decision:
    status: Status
    value: float | str
    probability: float | None = None
    confidence: float | None = None


def _first_status(options: tuple[tuple[bool, Status], ...], fallback: Status) -> Status:
    return next((status for matches, status in options if matches), fallback)


def _noul_decision(policy: Policy, answer: NoulAnswer, limited: bool) -> _Decision:
    value = answer.noul
    status = _first_status(
        (
            (all((value >= policy.warning_at, not limited)), "warning"),
            (value >= policy.uncertain_at, "uncertain_warning"),
        ),
        "unknown" if limited else "probably_legitimate",
    )
    return _Decision(status, value, probability=value)


def _choice_decision(policy: Policy, answer: ChoiceAnswer, limited: bool) -> _Decision:
    probability = answer.probabilities[answer.choice]
    confident = all(
        (
            probability >= policy.warning_at,
            answer.confidence >= policy.confidence_min,
            not limited,
        )
    )
    selected_risk = answer.choice in policy.warning_choices
    risk_support = max(answer.probabilities[label] for label in policy.warning_choices)
    status = _first_status(
        (
            (all((selected_risk, confident)), "warning"),
            (any((selected_risk, risk_support >= policy.uncertain_at)), "uncertain_warning"),
            (all((answer.choice in policy.legitimate_choices, confident)), "probably_legitimate"),
        ),
        "unknown",
    )
    return _Decision(status, answer.choice, probability, answer.confidence)


def _score_decision(policy: Policy, answer: ScoreAnswer, limited: bool) -> _Decision:
    status = _first_status(
        (
            (
                all(
                    (
                        answer.score >= policy.score_warning_at,
                        answer.confidence >= policy.confidence_min,
                        not limited,
                    )
                ),
                "warning",
            ),
            (answer.score >= policy.score_uncertain_at, "uncertain_warning"),
        ),
        "unknown" if answer.confidence < policy.confidence_min else "no_warning",
    )
    return _Decision(status, answer.score, confidence=answer.confidence)


def _decide(policy: Policy, answer: Answer, limited: bool) -> _Decision:
    if isinstance(answer, NoulAnswer):
        return _noul_decision(policy, answer, limited)
    if isinstance(answer, ChoiceAnswer):
        return _choice_decision(policy, answer, limited)
    assert isinstance(answer, ScoreAnswer)
    return _score_decision(policy, answer, limited)
