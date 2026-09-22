"""Behavior and ownership contracts for the small core/CLI architecture."""

import ast
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from jevproc.core.config import CacheSettings, _apply_override
from jevproc.core.corpus import load_corpus
from jevproc.core.experiments import CorpusExperiment
from jevproc.core.models import Assessment, RuleResult
from jevproc.core.storage import AnswerCache


@pytest.mark.parametrize("step", [1, 2, 3])
@pytest.mark.parametrize("error_type", [sqlite3.DatabaseError, KeyboardInterrupt])
def test_cache_setup_failure_always_releases_connection(tmp_path, monkeypatch, step, error_type):
    import jevproc.core.storage as storage

    calls = 0
    closed = []

    def operation(*args):
        nonlocal calls
        calls += 1
        if calls == step:
            raise error_type("synthetic setup failure")

    connection = SimpleNamespace(execute=operation, commit=operation, close=lambda: closed.append(True))
    monkeypatch.setattr(storage.sqlite3, "connect", lambda *args, **kwargs: connection)
    cache = AnswerCache.__new__(AnswerCache)
    with pytest.raises(error_type):
        cache.__init__(tmp_path / "cache", CacheSettings())
    assert closed == [True]
    assert not hasattr(cache, "db")


def test_config_patches_do_not_mutate_the_supplied_mapping():
    defaults = {"rulesets": {"process": [{"id": "JPR001", "policy": {"warning_at": 0.12}}]}}
    override = {"rulesets": {"process": [{"id": "JPR001", "policy": {"uncertain_at": 0.08}}]}}
    result = _apply_override(defaults, override)
    assert result["rulesets"]["process"][0]["policy"] == {"warning_at": 0.12, "uncertain_at": 0.08}
    assert defaults["rulesets"]["process"][0]["policy"] == {"warning_at": 0.12}
    assert "rulesets" in override


def test_corpus_accounting_preserves_every_raw_sample_and_review_contract():
    case = next(case for case in load_corpus().cases if case.label == "benign")
    experiment = CorpusExperiment([case], runs=2)
    for run in (1, 2):
        assessment = Assessment(
            process=case.process,
            status="uncertain_warning",
            model="jev-1.13.0",
            rules=[
                RuleResult(
                    rule="JPR001",
                    title="Process risk",
                    status="uncertain_warning",
                    answer={"type": "noul", "noul": 0.09},
                )
            ],
        )
        experiment.record(run, assessment)
    assert experiment.samples[case.id] == [0.09, 0.09]
    assert experiment.summary["samples"] == 2
    assert experiment.summary["mismatches"] == 0
    assert experiment.exit_code(False) == 0
    assert [item["run"] for item in experiment.ordered_results] == [1, 2]


def test_core_has_no_cli_dependency():
    root = Path(__file__).parents[1] / "src" / "jevproc" / "core"
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("jevproc.cli"), path
            elif isinstance(node, ast.Import):
                assert all(not item.name.startswith("jevproc.cli") for item in node.names), path
