"""Explicit synthetic demo through the real request/validation/policy pipeline."""

import json
from importlib.resources import files

import httpx

from jevproc.core.models import Snapshot


def demo_snapshot() -> Snapshot:
    return Snapshot.model_validate_json(files("jevproc").joinpath("data/demo-snapshot.json").read_bytes())


def demo_transport() -> httpx.MockTransport:
    fixtures = json.loads(files("jevproc").joinpath("data/demo-answers.json").read_text())

    def handle(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        answers = {}
        for key, question in payload["questions"].items():
            target = question["instructions"]["target"]["ref"]
            rule = key.removeprefix(target + "_")
            answer = fixtures.get(target, {}).get(rule)
            if answer is None or answer["type"] != question["type"]:
                return httpx.Response(422, json={"error": {"code": "unsupported_demo_rule"}})
            answers[key] = answer
        return httpx.Response(200, json={"model": payload["model"], "answers": answers,
                                        "usage": {"input_tokens": 0, "output_tokens": 0}})

    return httpx.MockTransport(handle)
