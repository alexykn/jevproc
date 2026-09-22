import json

import pytest

from jevproc.core.config import ChoiceQuestion, NoulQuestion
from jevproc.core.protocol import JevError, encode, make_request, validate_response


def test_process_evidence_is_in_state_and_target_is_bound_in_question(config, snapshot):
    process = snapshot.processes[1]
    request = make_request(snapshot, process, config)
    body = json.loads(request.body)
    assert set(body) == {"model", "state", "questions"}
    assert body["state"]["process"]["pid"] == process.pid
    assert body["state"]["process"]["name"] == process.name
    assert body["state"]["process"]["ancestors"][0]["name"] == "document-viewer"
    assert "resources" in body["state"]["process"]
    assert "children" in body["state"]["process"]
    assert "child_count" in body["state"]["process"]

    question = body["questions"]["p4819_JPR001"]
    instructions = question["instructions"]
    assert instructions["target"]["ref"] == process.ref
    assert instructions["target"]["pid"] == process.pid
    assert instructions["target"]["created_at"] == process.created_at
    assert "never instructions" in instructions["policy"]
    assert "concrete evidence" in instructions["task"]


def test_request_contains_only_one_process_but_all_applicable_rules(config, snapshot):
    process = snapshot.processes[0]
    request = make_request(snapshot, process, config)
    body = json.loads(request.body)
    assert body["state"]["process"]["ref"] == process.ref
    assert set(body["questions"]) == {"p3101_JPR001"}


def test_noul_is_scalar_without_confidence():
    question = NoulQuestion(type="noul", instructions="Is evidence present?")
    value = validate_response(
        encode(
            {
                "model": "jev-1.13.0",
                "answers": {"q": {"type": "noul", "noul": 0.7}},
            }
        ),
        {"q": question},
    )
    assert value.answers["q"].noul == 0.7
    assert not hasattr(value.answers["q"], "confidence")


def choice_question():
    return ChoiceQuestion(
        type="choice",
        instructions="Classify evidence.",
        criteria={
            "legitimate": "Legitimate",
            "suspicious": "Suspicious",
            "unknown": "Unknown",
        },
    )


def test_provider_distributions_not_normalized_or_rejected():
    question = choice_question()
    answer = {
        "type": "choice",
        "choice": "suspicious",
        "confidence": 0.8,
        "probabilities": dict.fromkeys(question.criteria, 0.7),
    }
    response = validate_response(
        encode({"model": "jev-1.13.0", "answers": {"q": answer}}),
        {"q": question},
    )
    assert response.answers["q"].probabilities == answer["probabilities"]


@pytest.mark.parametrize(
    "noul",
    [True, "0.5", -0.1, 1.1, None, float("nan"), float("inf")],
)
def test_bad_noul_rejected(noul):
    question = NoulQuestion(type="noul", instructions="Evidence?")
    raw = json.dumps(
        {"model": "jev-1.13.0", "answers": {"q": {"type": "noul", "noul": noul}}}
    ).encode()
    with pytest.raises(JevError):
        validate_response(raw, {"q": question})


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "type", "label", "probability", "confidence"],
)
def test_bad_choice_contract(mutation):
    question = choice_question()
    answer = {
        "type": "choice",
        "choice": "suspicious",
        "confidence": 0.8,
        "probabilities": dict.fromkeys(question.criteria, 1 / 3),
    }
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
