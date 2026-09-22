"""Local, testable warning policy. Model confidence is not threat severity."""

from jevproc.core.config import Rule
from jevproc.core.models import Assessment, Process, RuleResult, Status
from jevproc.core.protocol import Answer, ChoiceAnswer, NoulAnswer, ScoreAnswer, applicable

VISIBLE: frozenset[str] = frozenset({"warning", "uncertain_warning"})


def evidence_limited(rule: Rule, process: Process) -> bool:
    sources = rule.requires or ["executable", "name", "identity"]
    return any(process.coverage.get(source) != "observed" for source in sources)


def skipped_rule(rule: Rule, process: Process) -> RuleResult:
    missing = [s for s in rule.requires if process.coverage.get(s) not in {"observed", "partial", "truncated"}]
    if missing:
        details = ", ".join(f"{s}={process.coverage.get(s, 'unavailable')}" for s in missing)
        return RuleResult(rule=rule.id, title=rule.title, status="unknown", message=f"Not evaluated: {details}.")
    return RuleResult(rule=rule.id, title=rule.title, status="not_applicable",
                      message="No relevant evidence items were observed; this is not proof of absence.")


def judge(rule: Rule, process: Process, answer: Answer) -> RuleResult:
    policy = rule.policy
    limited = evidence_limited(rule, process)
    status: Status
    probability = None
    confidence = None
    if isinstance(answer, NoulAnswer):
        value = probability = answer.noul
        if value >= policy.warning_at and not limited:
            status = "warning"
        elif value >= policy.uncertain_at:
            status = "uncertain_warning"
        elif value > 1 - policy.uncertain_at:
            status = "unknown"
        else:
            status = "no_warning"
    elif isinstance(answer, ChoiceAnswer):
        value, confidence = answer.choice, answer.confidence
        probability = answer.probabilities[answer.choice]
        # Do not add non-normalized provider values into a made-up malware probability.
        risk_support = max(answer.probabilities[label] for label in policy.warning_choices)
        selected_risk = answer.choice in policy.warning_choices
        if selected_risk and probability >= policy.warning_at and confidence >= policy.confidence_min and not limited:
            status = "warning"
        elif selected_risk or risk_support >= policy.uncertain_at:
            status = "uncertain_warning"
        elif answer.choice in policy.legitimate_choices and probability >= policy.warning_at and confidence >= policy.confidence_min and not limited:
            status = "probably_legitimate"
        else:
            status = "unknown"
    else:
        assert isinstance(answer, ScoreAnswer)
        value, confidence = answer.score, answer.confidence
        if value >= policy.score_warning_at and confidence >= policy.confidence_min and not limited:
            status = "warning"
        elif value >= policy.score_uncertain_at:
            status = "uncertain_warning"
        elif confidence < policy.confidence_min:
            status = "unknown"
        else:
            status = "no_warning"
    message = rule.message if status in VISIBLE else ""
    if limited and status in VISIBLE:
        message += " Relevant evidence is partial or unavailable; this finding remains uncertain."
    return RuleResult(rule=rule.id, title=rule.title, status=status, message=message,
                      value=value, probability=probability, confidence=confidence,
                      answer=answer.model_dump(mode="json"))


def aggregate(rules: list[RuleResult]) -> Status:
    statuses = {r.status for r in rules}
    for status in ("warning", "uncertain_warning", "unknown"):
        if status in statuses:
            return status
    if "probably_legitimate" in statuses:
        return "probably_legitimate"
    return "no_warning" if "no_warning" in statuses else "not_evaluated"


def assess(process: Process, rules: list[Rule], answers: dict[str, Answer], model: str, cached: bool) -> Assessment:
    results = [judge(rule, process, answers[f"{process.ref}_{rule.id}"]) if applicable(rule, process)
               else skipped_rule(rule, process) for rule in rules]
    return Assessment(process=process, status=aggregate(results), rules=results, cached=cached, model=model)
