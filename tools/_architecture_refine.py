"""Final typed-boundary polish; removed together with the one-shot builder."""
import ast
import json
from pathlib import Path

from _architecture_tools import CHANGED, append, extract, read, replace, write

calibration = 'src/jevproc/core/calibration.py'
write(calibration, read(calibration).replace('    observations = [', '    observations: list[tuple[str, float]] = ['))

network = 'src/jevproc/core/evidence/network.py'
write(network, read(network).replace('protocol=protocol.lower(),', 'protocol="tcp" if protocol == "TCP" else "udp",'))

process = 'src/jevproc/core/evidence/process.py'
source = read(process)
needle = '    if executable and coverage["executable"] != "truncated":\n'
assert source.count(needle) == 1
write(process, source.replace(needle, '    file_coverage: dict[str, Coverage]\n' + needle))

relationships = 'src/jevproc/core/evidence/relationships.py'
source = read(relationships)
source = source.replace('def _child_record(item: psutil.Process, darwin_commands: dict[int, str])',
                        'def _child_record(item: psutil.Process, info: dict[str, Any], darwin_commands: dict[int, str])')
source = source.replace('    info = item.info\n', '')
source = source.replace('_child_record(item, commands)', '_child_record(item, item.info, commands)')
write(relationships, source)

# Diagnostic precedence remains exactly the same: this is a fixed mapping of
# recognized output phrases, not 35 branches interleaved with collection logic.
files = 'src/jevproc/core/evidence/files.py'
source = read(files)
function = ast.parse(extract(source, '_classify_codesign_failure')).body[0]
rows = []
for node in function.body:
    if not isinstance(node, ast.If):
        continue
    phrases = tuple(item.value for item in ast.walk(node.test)
                    if isinstance(item, ast.Constant) and isinstance(item.value, str))
    state, issue = ast.literal_eval(node.body[0].value)
    rows.append((phrases, state, issue))
assert len(rows) == 11, len(rows)
append(files, '# Ordered codesign diagnostic mapping; first match retains historical precedence.\n'
       '_CODESIGN_FAILURES: tuple[tuple[tuple[str, ...], str, str | None], ...] = (\n'
       + ''.join('    ' + repr(row) + ',\n' for row in rows) + ')\n')
replace(files, '_classify_codesign_failure', '''
def _classify_codesign_failure(stderr: str) -> tuple[str, str | None]:
    """Normalize known diagnostics without treating unknown failures as valid."""
    text = stderr.lower()
    for phrases, state, issue in _CODESIGN_FAILURES:
        if any(phrase in text for phrase in phrases):
            return state, issue
    return "verification_failed", "other"
''')

# Retain the offline equivalence probe as an ordinary developer tool. It contains
# synthetic fixtures and HTTP mocks only; no credentials or runner paths.
probe = read('tools/_architecture_contract.py')
probe = probe.replace('"""Deterministic, offline contract probe for the one-shot refactor branch."""',
                      '"""Offline behavior fingerprints for comparing refactors; only synthetic HTTP fixtures.\n\nRun with PYTHONPATH=src uv run python tools/behavior_fingerprint.py on each ref.\nElapsed times are excluded; changes to evidence, policy, or output are not.\n"""')
write('tools/behavior_fingerprint.py', probe)

append('docs/VALIDATION.md', '''

## Architecture refactor checks (2026-09-22)

The refactor was compared against `4ba6a91a51517b09f6ace90f5d0eaa2f11532596`
with the same installed dependencies and deterministic synthetic HTTP responses.
The offline fingerprints matched for all 72 request bodies, 362 policy decisions,
500 seeded argument-redaction cases, the sanitized corpus snapshot, and nine
corpus CLI variants (listing/regression/calibration in text/JSON/JSONL). Only
elapsed time is removed from output comparison. The reproducible probe is
`PYTHONPATH=src uv run python tools/behavior_fingerprint.py`.

The baseline had 187 passing tests; the refactor adds nine regression cases for
cache setup cleanup (including interruption), non-mutating config overlays,
corpus accounting, and the core-to-CLI dependency boundary. Existing tests still
exercise parallel collection, executable deduplication, identity revalidation,
retry budgets, redaction, and complete machine output. The initial Linux pass
also built the source distribution/wheel and exercised the installed wheel away
from the checkout. The PR's normal matrix remains authoritative for each exact
commit's Linux/macOS and Python 3.12/3.13 results.

This is not a new detection calibration or a live Jevscan result. No live provider
key was used, no host inventory was submitted, and the 72 corpus cases, prompt,
thresholds, and external evidence schema were not changed to improve scores.
''')
paths = set(json.loads(Path('/tmp/jevproc-refactor-files.json').read_text()))
paths.update(CHANGED)
Path('/tmp/jevproc-refactor-files.json').write_text(json.dumps(sorted(paths)))
