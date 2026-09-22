"""Deterministic, offline contract probe for the one-shot refactor branch."""
import contextlib
import hashlib
import io
import itertools
import json
import os
import random
import re
from unittest.mock import patch

import httpx

import jevproc.cli.corpus as corpus_cli
from jevproc.core.assessment import judge
from jevproc.core.client import JevClient
from jevproc.core.config import Rule, load_config
from jevproc.core.corpus import load_corpus, snapshot_for
from jevproc.core.privacy import redact_argv, sanitize_snapshot
from jevproc.core.protocol import ChoiceAnswer, NoulAnswer, ScoreAnswer, make_request


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def canonical(value):
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in value.items() if key != "elapsed_seconds"}
    if isinstance(value, list):
        return [canonical(item) for item in value]
    return value


config = load_config()
corpus = load_corpus()
snapshot = snapshot_for(corpus, list(corpus.cases))
wire = [hashlib.sha256(make_request(snapshot, p, config).body).hexdigest() for p in snapshot.processes]

results = []
processes = [snapshot.processes[0], snapshot.processes[-1]]
for process in processes:
    for value in [i / 100 for i in range(101)] + [.079, .119]:
        results.append(judge(config.active_rules[0], process, NoulAnswer(type="noul", noul=value)).model_dump())
choice_rule = Rule.model_validate({
    "id": "LOCALC", "title": "test", "message": "review",
    "question": {"type": "choice", "instructions": "Classify evidence.",
                 "criteria": {"legitimate": "Legitimate", "suspicious": "Suspicious", "unknown": "Unknown"}},
    "policy": {"warning_choices": ["suspicious"], "legitimate_choices": ["legitimate"]},
})
for process, label, p, confidence, risk in itertools.product(
        processes, ["legitimate", "suspicious", "unknown"], [.4, .85, .96], [.1, .7, .9], [.01, .7]):
    probabilities = {"legitimate": .01, "suspicious": risk, "unknown": .01}
    probabilities[label] = p
    answer = ChoiceAnswer(type="choice", choice=label, confidence=confidence, probabilities=probabilities)
    results.append(judge(choice_rule, process, answer).model_dump())
score_rule = Rule.model_validate({"id": "LOCALS", "title": "test", "message": "review",
    "question": {"type": "score", "instructions": "Evaluate evidence.", "criteria": ["none", "weak", "substantial", "strong"]}})
for process, value, confidence in itertools.product(processes, [0., .5, 1.49, 1.5, 1.99, 2., 2.5, 3.], [.1, .7, .99]):
    answer = ScoreAnswer(type="score", score=value, confidence=confidence, probabilities={str(i): .25 for i in range(4)})
    results.append(judge(score_rule, process, answer).model_dump())

rng = random.Random(818)
words = ["tool", "--token", "secret", "Bearer", "Basic", "--header", "--password=value", "-p", "--foo", "--api_key", "x" * 900,
         "Authorization: Bearer secret", "https://user:password@example.test/?token=value", "/Users/test/project"]
arguments = [[rng.choice(words) for _ in range(rng.randrange(1, 80))] for _ in range(500)]
redacted = [redact_argv(row) for row in arguments]

by_pid = {case.process.pid: case for case in corpus.cases}
async def handler(request):
    body = json.loads(request.content)
    case = by_pid[body["state"]["process"]["pid"]]
    score = {"benign": .07, "ambiguous": .09, "suspicious": .2, "unknown": .04}[case.label]
    return httpx.Response(200, json={"model": body["model"],
        "answers": {key: {"type": "noul", "noul": score} for key in body["questions"]},
        "usage": {"input_tokens": 10, "output_tokens": 1}})

def mock_client(settings, api_key, *, base_url):
    return JevClient(settings, "synthetic-contract-key", base_url="http://localhost", transport=httpx.MockTransport(handler))

outputs = []
with patch.object(corpus_cli, "JevClient", mock_client), patch.dict(os.environ, {"TYPESAFE_API_KEY": "synthetic-contract-key"}):
    for mode, format_name in itertools.product(["--list", "regression", "--calibrate"], ["text", "json", "jsonl"]):
        args = ["--format", format_name, "--runs", "2", "--color", "never"]
        if mode != "regression":
            args.append(mode)
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = corpus_cli.main(args)
        text = stream.getvalue()
        if format_name == "json":
            output = canonical(json.loads(text))
        elif format_name == "jsonl" and mode != "--list":
            output = canonical([json.loads(line) for line in text.splitlines()])
        else:
            output = re.sub(r"elapsed=[0-9.]+s", "elapsed=<time>s", text)
        outputs.append([mode, format_name, code, output])

print(json.dumps({"wire_requests": len(wire), "wire_digest": digest(wire),
    "decisions": len(results), "decision_digest": digest(results),
    "redactions": len(redacted), "redaction_digest": digest(redacted),
    "sanitized_snapshot_digest": digest(sanitize_snapshot(snapshot, True).model_dump()),
    "cli_variants": len(outputs), "cli_digest": digest(outputs)}, sort_keys=True, indent=2))
