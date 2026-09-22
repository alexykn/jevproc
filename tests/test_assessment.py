import pytest

from jevproc.core.assessment import judge
from jevproc.core.config import Rule
from jevproc.core.protocol import ChoiceAnswer, NoulAnswer, ScoreAnswer


@pytest.mark.parametrize("value,status", [(0.1,"no_warning"),(.5,"unknown"),(.6,"uncertain_warning"),(.849,"uncertain_warning"),(.85,"warning"),(.99,"warning")])
def test_noul_boundaries(config, snapshot, value, status):
    result = judge(config.active_rules[2], snapshot.processes[0], NoulAnswer(type="noul", noul=value))
    assert result.status == status
    assert result.confidence is None


def test_high_probability_with_partial_evidence_is_only_tentative(config, snapshot):
    p = snapshot.processes[0]
    p = p.model_copy(update={"coverage": {**p.coverage, "file": "partial"}})
    result = judge(config.active_rules[2], p, NoulAnswer(type="noul", noul=.99))
    assert result.status == "uncertain_warning"
    assert "partial" in result.message


@pytest.mark.parametrize("choice,p,confidence,status", [
    ("suspicious",.95,.9,"warning"),
    ("probably_malicious",.95,.1,"uncertain_warning"),
    ("suspicious",.4,.9,"uncertain_warning"),
    ("unknown",.9,.9,"unknown"),
    ("probably_legitimate",.96,.9,"probably_legitimate"),
    ("probably_legitimate",.6,.4,"unknown"),
])
def test_choice_policy(config, snapshot, choice, p, confidence, status):
    probs = {key: .01 for key in config.active_rules[0].question.criteria}
    probs[choice] = p
    result = judge(config.active_rules[0], snapshot.processes[0], ChoiceAnswer(type="choice", choice=choice, confidence=confidence, probabilities=probs))
    assert result.status == status


def test_risk_values_are_not_summed(config, snapshot):
    answer = ChoiceAnswer(type="choice", choice="unknown", confidence=.5,
                          probabilities={"probably_legitimate":.1,"suspicious":.4,"probably_malicious":.4,"unknown":.8})
    assert judge(config.active_rules[0], snapshot.processes[0], answer).status == "unknown"


@pytest.mark.parametrize("score,conf,status", [(2.5,.9,"warning"),(2.5,.2,"uncertain_warning"),(1.7,.9,"uncertain_warning"),(.5,.9,"no_warning"),(.5,.1,"unknown")])
def test_custom_score_policy(snapshot, score, conf, status):
    rule = Rule.model_validate({"id":"LOCAL1","title":"test","message":"review",
                                "question":{"type":"score","instructions":"Evaluate evidence.","criteria":["none","weak","substantial","strong"]}})
    answer = ScoreAnswer(type="score",score=score,confidence=conf,probabilities={str(i):.25 for i in range(4)})
    assert judge(rule,snapshot.processes[0],answer).status == status
