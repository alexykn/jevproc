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


def aggregate(rules: list[RuleResult]) -> Status:
    statuses = {r.status for r in rules}
    for status in ("warning", "uncertain_warning", "unknown"):
        if status in statuses:
            return status
    if "probably_legitimate" in statuses:
        return "probably_legitimate"
    return "no_warning" if "no_warning" in statuses else "not_evaluated"


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


def _noul_decision(policy: Policy, answer: NoulAnswer, limited: bool) -> _Decision:
    value = answer.noul
    if value >= policy.warning_at and not limited:
        status: Status = "warning"
    elif value >= policy.uncertain_at:
        status = "uncertain_warning"
    else:
        status = "unknown" if limited else "probably_legitimate"
    return _Decision(status, value, probability=value)


def _choice_decision(policy: Policy, answer: ChoiceAnswer, limited: bool) -> _Decision:
    probability = answer.probabilities[answer.choice]
    confident = probability >= policy.warning_at and answer.confidence >= policy.confidence_min and not limited
    selected_risk = answer.choice in policy.warning_choices
    # Provider supports need not sum to one: never synthesize a summed risk.
    risk_support = max(answer.probabilities[label] for label in policy.warning_choices)
    if selected_risk and confident:
        status: Status = "warning"
    elif selected_risk or risk_support >= policy.uncertain_at:
        status = "uncertain_warning"
    elif answer.choice in policy.legitimate_choices and confident:
        status = "probably_legitimate"
    else:
        status = "unknown"
    return _Decision(status, answer.choice, probability, answer.confidence)


def _score_decision(policy: Policy, answer: ScoreAnswer, limited: bool) -> _Decision:
    if answer.score >= policy.score_warning_at and answer.confidence >= policy.confidence_min and not limited:
        status: Status = "warning"
    elif answer.score >= policy.score_uncertain_at:
        status = "uncertain_warning"
    else:
        status = "unknown" if answer.confidence < policy.confidence_min else "no_warning"
    return _Decision(status, answer.score, confidence=answer.confidence)


def _decide(policy: Policy, answer: Answer, limited: bool) -> _Decision:
    if isinstance(answer, NoulAnswer):
        return _noul_decision(policy, answer, limited)
    if isinstance(answer, ChoiceAnswer):
        return _choice_decision(policy, answer, limited)
    assert isinstance(answer, ScoreAnswer)
    return _score_decision(policy, answer, limited)
