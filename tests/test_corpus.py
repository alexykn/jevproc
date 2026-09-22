import json

import httpx
import pytest

import jevproc.cli.corpus as corpus_cli
from jevproc.core.client import JevClient as RealJevClient
from jevproc.core.corpus import load_corpus, matches, selected_cases, snapshot_for


def test_packaged_corpus_shape():
    corpus = load_corpus()
    assert len(corpus.cases) == 7
    assert len({case.id for case in corpus.cases}) == 7
    assert sum(case.expected_statuses == ["warning"] for case in corpus.cases) == 4
    assert corpus.host.platform == "fixture"


def test_corpus_selection_and_snapshot():
    corpus = load_corpus()
    cases = selected_cases(corpus, ["root-user-writable-masquerade", "benign-build-tool"])
    snapshot = snapshot_for(corpus, cases)
    assert snapshot.synthetic
    assert [process.pid for process in snapshot.processes] == [9101, 9201]
    with pytest.raises(ValueError, match="unknown corpus case"):
        selected_cases(corpus, ["does-not-exist"])


def test_match_policy_is_explicit():
    corpus = load_corpus()
    ambiguous = next(case for case in corpus.cases if case.id == "document-shell-ambiguous")
    assert matches(ambiguous, "warning")
    assert matches(ambiguous, "uncertain_warning")
    assert not matches(ambiguous, "probably_legitimate")


def test_list_does_not_require_api_key(capsys, monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert corpus_cli.main(["--list"]) == 0
    text = capsys.readouterr().out
    assert "root-user-writable-masquerade" in text
    assert "benign-build-tool" in text


def test_live_corpus_harness_with_mock_provider(capsys, monkeypatch):
    corpus = load_corpus()
    by_pid = {case.process.pid: case for case in corpus.cases}

    def transport():
        async def handler(request):
            payload = json.loads(request.content)
            process = payload["state"]["process"]
            case = by_pid[process["pid"]]
            if case.expected_statuses == ["warning"]:
                value = 0.95
            elif "uncertain_warning" in case.expected_statuses:
                value = 0.65
            else:
                value = 0.05
            answers = {
                key: {"type": "noul", "noul": value}
                for key in payload["questions"]
            }
            return httpx.Response(
                200,
                json={
                    "model": payload["model"],
                    "answers": answers,
                    "usage": {"input_tokens": 10, "output_tokens": 1},
                },
            )
        return httpx.MockTransport(handler)

    def client(settings, api_key, *, base_url):
        return RealJevClient(
            settings,
            api_key or "test-key",
            base_url="http://localhost",
            transport=transport(),
        )

    monkeypatch.setattr(corpus_cli, "JevClient", client)
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-key")
    assert corpus_cli.main(["--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["cases"] == 7
    assert result["summary"]["passed"] == 7
    assert result["summary"]["mismatches"] == 0
    assert result["summary"]["requests"] == 7
