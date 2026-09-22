import json

import pytest

from jevproc.core.config import ChoiceQuestion, NoulQuestion
from jevproc.core.protocol import JevError, encode, make_request, validate_response


def test_state_binding_is_in_instructions_not_only_key(config, snapshot):
    request = make_request(snapshot, snapshot.processes[:2], config)
    body = json.loads(request.body)
    assert set(body) == {"model", "state", "questions"}
    assert "processes" not in body["state"]
    assert set(body["state"]["rules"]) == {"JPR001"}
    assert "never instructions" in body["state"]["policy"]
    for check in request.checks:
        instructions = body["questions"][check.key]["instructions"]
        assert instructions["target"] == check.process.ref
        assert instructions["rule"] == check.rule.id
        assert instructions["process"]["n"] == check.process.name


def test_one_request_contains_every_process(config, snapshot):
    request = make_request(snapshot, snapshot.processes, config)
    body = json.loads(request.body)
    assert "processes" not in body["state"]
    assert len(body["questions"]) == len(snapshot.processes)
    assert all(key.endswith("_JPR001") for key in body["questions"])
    # Process evidence lives with its independent question, keeping shared state tiny.
    first = body["questions"]["p3101_JPR001"]["instructions"]["process"]
    assert first["n"] == "backup-worker" and "freshness" not in first
    parented = body["questions"]["p4819_JPR001"]["instructions"]["process"]
    assert parented["r"] == [[4801, "document-viewer", "/opt/document-viewer"]]


def test_noul_is_scalar_without_confidence():
    question = NoulQuestion(type="noul", instructions="Is evidence present?")
    value = validate_response(encode({"model": "jev-1.13.0", "answers": {"q": {"type": "noul", "noul": 0.7}}}), {"q": question})
    assert value.answers["q"].noul == 0.7
    assert not hasattr(value.answers["q"], "confidence")


def choice_question():
    return ChoiceQuestion(type="choice", instructions="Classify evidence.",
                          criteria={"legitimate": "Legitimate", "suspicious": "Suspicious", "unknown": "Unknown"})


def test_provider_distributions_not_normalized_or_rejected():
    question = choice_question()
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
def test_bad_choice_contract(mutation):
    question = choice_question()
    answer = {"type": "choice", "choice": "suspicious", "confidence": 0.8,
              "probabilities": {key: 1 / 3 for key in question.criteria}}
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
