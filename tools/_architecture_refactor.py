"""One-shot checked transformation. This file is removed from the resulting tree."""
import ast
import json
from pathlib import Path

import _architecture_core
import _architecture_corpus
import _architecture_evidence
from _architecture_tools import CHANGED, ROOT, append, read, write

_architecture_core.apply()
_architecture_evidence.apply()
_architecture_corpus.apply()

# The extracted summary uses the existing scan mode to label synthetic results.
engine = 'src/jevproc/core/engine.py'
code = read(engine)
code = code.replace('after: tuple[int, int, int, int], started: float) -> dict:',
                    'after: tuple[int, int, int, int], started: float, mode: str) -> dict:')
code = code.replace('_scan_summary(snapshot, assessments, before, self._counters(), started))',
                    '_scan_summary(snapshot, assessments, before, self._counters(), started, mode))')
write(engine, code)

write('tests/test_architecture_contracts.py', '''
"""Behavior and ownership contracts for the small core/CLI architecture."""
import ast
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from jevproc.core.config import CacheSettings, _apply_override
from jevproc.core.storage import AnswerCache
from jevproc.core.corpus import load_corpus
from jevproc.core.experiments import CorpusExperiment
from jevproc.core.models import Assessment, RuleResult


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
    defaults = {"rulesets": {"process": [{"id": "JPR001", "policy": {"warning_at": .12}}]}}
    override = {"rulesets": {"process": [{"id": "JPR001", "policy": {"uncertain_at": .08}}]}}
    result = _apply_override(defaults, override)
    assert result["rulesets"]["process"][0]["policy"] == {"warning_at": .12, "uncertain_at": .08}
    assert defaults["rulesets"]["process"][0]["policy"] == {"warning_at": .12}
    assert "rulesets" in override


def test_corpus_accounting_preserves_every_raw_sample_and_review_contract():
    case = next(case for case in load_corpus().cases if case.label == "benign")
    experiment = CorpusExperiment([case], runs=2)
    for run in (1, 2):
        assessment = Assessment(process=case.process, status="uncertain_warning", model="jev-1.13.0", rules=[
            RuleResult(rule="JPR001", title="Process risk", status="uncertain_warning", answer={"type": "noul", "noul": .09})
        ])
        experiment.record(run, assessment)
    assert experiment.samples[case.id] == [.09, .09]
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
''')

append('docs/ARCHITECTURE.md', '''

## Maintaining the small-project boundaries

The CLI owns arguments, terminal formatting, and application composition. Core
owns evidence, typed provider contracts, policy decisions, and result accounting.
Keep that dependency direction; core must not import the CLI.

- `core/collector.py` coordinates the existing bounded parallel phases. It does
  not implement signing diagnostics, argument reads, or relationship traversal.
- `core/evidence/process.py` owns identity, redacted invocation, and resource reads.
- `core/evidence/files.py` owns on-disk metadata, hash limits, signing diagnostics,
  and stable-file checks. It never infers a process risk verdict.
- `core/evidence/network.py` owns socket collection and instance revalidation.
- `core/evidence/relationships.py` owns ancestry, children, and family selection.
- `core/experiments.py` records every synthetic sample, repeats scans, and prepares
  calibration inputs. `cli/corpus_render.py` only presents those results.
- `core/client.py` separates response buffering, permanent error interpretation,
  retry scheduling, and successful-answer validation/accounting.
- `core/assessment.py` has independent Noul, Choice, and Score decision functions;
  `judge` adds the common evidence qualification and result envelope.
- `core/storage.py` validates filesystem ownership before acquiring SQLite and
  transfers connection ownership only after initialization succeeds. Setup errors
  close the connection; they do not delete an existing cache or suppress errors.

There is deliberately no plugin system, dependency-injection container, generic
repository layer, event bus, or parallel implementation of the detector. Private
backend tests patch the backend that owns an operation. `collect`, `load_config`,
`judge`, `Engine.scan`, `JevClient.evaluate`, and both CLI entry points keep their
established contracts.

The refactor does not change the Jev question, thresholds, process-state schema,
packaged corpus, collection limits, thread-pool concurrency, or warnings-first
output. No additional resource monitor or collection progress display is added.
''')

changelog = 'CHANGELOG.md'
write(changelog, read(changelog).replace('## Unreleased\n', '''## Unreleased

- Separate evidence backends from parallel collection orchestration.
- Separate synthetic experiment execution/accounting from corpus CLI rendering.
- Clarify answer-type policy dispatch, configuration merging, redaction, and transport retry paths.
- Close SQLite connections if cache initialization fails before ownership transfer.
''', 1))

# Remove an outdated duplicate paragraph contradicting live parent resolution.
architecture = 'docs/ARCHITECTURE.md'
text = read(architecture)
text = text.replace('Ancestry is bounded, drawn from selected snapshot records, and checks chronology\nand cycles. Parents outside that selection are missing evidence. Network data is\na local/remote socket snapshot, with neither traffic direction nor contents.\n',
                    'Network data is a local/remote socket snapshot, with neither traffic direction nor contents.\n')
write(architecture, text)

for path in sorted(CHANGED):
    if path.endswith('.py'):
        ast.parse(read(path), filename=path)
Path('/tmp/jevproc-refactor-files.json').write_text(json.dumps(sorted(CHANGED)))
print('Refactored files:', *sorted(CHANGED), sep='\n  ')
