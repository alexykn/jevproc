"""Local, testable warning policy. Model confidence is not threat severity."""

from dataclasses import dataclass
from functools import singledispatch

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


def _missing_sources(rule: Rule, process: Process) -> list[str]:
    available = {"observed", "partial", "truncated"}
    return [source for source in rule.requires if process.coverage.get(source) not in available]


def _missing_message(missing: list[str], process: Process) -> str:
    details = ", ".join(f"{source}={process.coverage.get(source, 'unavailable')}" for source in missing)
    return f"Not evaluated: {details}."


def skipped_rule(rule: Rule, process: Process) -> RuleResult:
    missing = _missing_sources(rule, process)
    status: Status = "unknown" if missing else "not_applicable"
    message = (
        _missing_message(missing, process)
        if missing
        else "No relevant evidence items were observed; this is not proof of absence."
    )
    return RuleResult(rule=rule.id, title=rule.title, status=status, message=message)


def _decision_message(rule: Rule, status: Status, limited: bool) -> str:
    visible = status in VISIBLE
    suffix = " Relevant evidence is partial or unavailable; this finding remains uncertain." if limited and visible else ""
    return (rule.message if visible else "") + suffix


def judge(rule: Rule, process: Process, answer: Answer) -> RuleResult:
    limited = evidence_limited(rule, process)
    decision = _decide(rule.policy, answer, limited)
    return RuleResult(
        rule=rule.id,
        title=rule.title,
        status=decision.status,
        message=_decision_message(rule, decision.status, limited),
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


_AGGREGATE_RANK = {status: index for index, status in enumerate(_AGGREGATE_PRIORITY)}


def aggregate(rules: list[RuleResult]) -> Status:
    return min(
        (result.status for result in rules),
        key=lambda status: _AGGREGATE_RANK.get(status, len(_AGGREGATE_PRIORITY)),
        default="not_evaluated",
    )


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


@singledispatch
def _answer_decision(answer: Answer, policy: Policy, limited: bool) -> _Decision:
    raise TypeError(f"unsupported answer type: {type(answer).__name__}")


@_answer_decision.register
def _noul_answer_decision(answer: NoulAnswer, policy: Policy, limited: bool) -> _Decision:
    return _noul_decision(policy, answer, limited)


@_answer_decision.register
def _choice_answer_decision(answer: ChoiceAnswer, policy: Policy, limited: bool) -> _Decision:
    return _choice_decision(policy, answer, limited)


@_answer_decision.register
def _score_answer_decision(answer: ScoreAnswer, policy: Policy, limited: bool) -> _Decision:
    return _score_decision(policy, answer, limited)


def _decide(policy: Policy, answer: Answer, limited: bool) -> _Decision:
    return _answer_decision(answer, policy, limited)
