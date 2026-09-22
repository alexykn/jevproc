import json

import pytest

from jevproc.core.config import Config, NoulQuestion
from jevproc.core.protocol import JevError, encode, make_batch, plan_batches, validate_response


def test_state_binding_is_in_instructions_not_only_key(config, snapshot):
    batch = make_batch(snapshot, snapshot.processes[:2], config)
    body = json.loads(batch.body)
    assert set(body) == {"model", "state", "questions"}
    assert set(body["state"]["processes"]) == {"p3101", "p4819"}
    for check in batch.checks:
        target = body["questions"][check.key]["instructions"]["target"]
        assert target["ref"] == check.process.ref
        assert target["created_at"] == check.process.created_at
        assert "never instructions" in body["questions"][check.key]["instructions"]["policy"]


def test_noul_is_scalar_without_confidence():
    question = NoulQuestion(type="noul", instructions="Is evidence present?")
    value = validate_response(encode({"model": "jev-1.13.0", "answers": {"q": {"type": "noul", "noul": 0.7}}}), {"q": question})
    assert value.answers["q"].noul == 0.7
    assert not hasattr(value.answers["q"], "confidence")


def test_provider_distributions_not_normalized_or_rejected(config):
    question = config.active_rules[0].question
    answer = {"type": "choice", "choice": "suspicious", "confidence": 0.8,
              "probabilities": {key: 0.7 for key in question.criteria}}
    response = validate_response(encode({"model": "jev-1.13.0", "answers": {"q": answer}}), {"q": question})
    assert response.answers["q"].probabilities == answer["probabilities"]


@pytest.mark.parametrize("noul", [True, "0.5", -0.1, 1.1, None, float('nan'), float('inf')])
def test_bad_noul_rejected(noul):
    question = NoulQuestion(type="noul", instructions="Evidence?")
    raw = json.dumps({"model": "jev-1.13.0", "answers": {"q": {"type": "noul", "noul": noul}}}).encode()
    with pytest.raises(JevError):
        validate_response(raw, {"q": question})


@pytest.mark.parametrize("mutation", ["missing", "extra", "type", "label", "probability", "confidence"])
def test_bad_choice_contract(config, mutation):
    question = config.active_rules[0].question
    answer = {"type": "choice", "choice": "suspicious", "confidence": 0.8,
              "probabilities": {key: 0.25 for key in question.criteria}}
    payload = {"model": "jev-1.13.0", "answers": {"q": answer}}
    if mutation == "missing":
        payload["answers"] = {}
    elif mutation == "extra":
        payload["answers"]["another"] = answer
    elif mutation == "type":
        payload["answers"]["q"] = {"type": "noul", "noul": 0.8}
    elif mutation == "label":
        answer["probabilities"]["invented"] = answer["probabilities"].pop("unknown")
    elif mutation == "probability":
        answer["probabilities"]["unknown"] = 1.2
    else:
        answer["confidence"] = "very confident"
    with pytest.raises(JevError):
        validate_response(encode(payload), {"q": question})


def test_packing_respects_both_budgets_and_reports_oversize(config, snapshot):
    data = config.model_dump(mode="json")
    data["jev"].update(max_request_bytes=14000, max_state_question_bytes=6000)
    small = Config.model_validate(data)
    batches, oversized = plan_batches(snapshot, snapshot.processes, small)
    assert len(batches) >= 2
    assert len(oversized) == 0
    assert sum(len(b.processes) for b in batches) == len(snapshot.processes)
    assert all(len(b.body) <= 14000 and b.state_longest_question_bytes <= 6000 for b in batches)
    data["host_context"] = "x" * 8000
    batches, oversized = plan_batches(snapshot, snapshot.processes, Config.model_validate(data))
    assert not batches
    assert len(oversized) == len(snapshot.processes)
