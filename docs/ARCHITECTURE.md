# Architecture and contracts

```text
psutil snapshot or validated saved JSON
  -> privacy minimization + bounded typed Process records
  -> independent rule applicability checks
  -> bounded shared-state request batches
  -> validated cache / paced Jev client
  -> exact typed answers
  -> local warning policy
  -> warnings-first text OR complete versioned JSON/JSONL
```

`core/models.py` owns external snapshot and report records. `collector.py` owns
OS access, permission gaps, lifecycle checks and on-disk inspection. `privacy.py`
minimizes imported and collected data. `config.py` validates explicit operator
policy. `protocol.py` binds targets and owns response validation; `client.py`
handles only transport, pacing and request accounting. `assessment.py` applies
local policy. `engine.py` owns orchestration. `cli` never invents a second detector.

## Shared state, not duplicated per-question prompts

A request contains one `state.processes` mapping. Each question's instruction
object explicitly names its `target.ref`, PID and creation time and includes the
policy and task. The provider's API says question IDs are not passed to the model;
using only a key such as `p123_JPR001` would therefore be incorrect. The key is a
local attribution handle; the instructions perform the semantic binding.

Question independence is intentional. Overall assessment does not consume the
other model answers, and the dimensions do not consume each other. Relationships
between observed processes are context; they are not fabricated execution history.
There is no hidden agent/tool loop, shell execution or model-written remediation.

The boundary checks exact answer IDs, answer types, criterion labels, finite ranges
and score scale. Choice/Score numeric distributions are preserved without
normalization. Cached answers use the same decoder. Pinned-model mismatches are
errors, not transparent model substitutions. Noul has no invented confidence.

## Collection and evidence limits

Creation time accompanies each PID. A fresh psutil object checks identity and the
executable path after collection. Reused PIDs, changed executable paths, exits and
unverifiable identities are not submitted for classification. Socket enumeration
occurs between initial identity capture and that recheck, reducing misattribution
across PID reuse. This does **not** make the snapshot atomic or detect every exec,
in-place binary replacement, injected module, or memory-only compromise.

Ancestry is bounded, drawn from selected snapshot records, and checks chronology
and cycles. Parents outside that selection are missing evidence. Network data is
a local/remote socket snapshot, with neither traffic direction nor contents.
Limited-access enumeration is marked partial; absent entries are not safe entries.

File evidence is obtained afresh per process rather than trusted by pathname.
Optional hashes require a regular file, a size limit and stable before/after file
metadata during the read. The final file component is not followed as a symlink.
This is not a cryptographic binding to the loaded image or the complete filesystem
path. macOS signature checks have a subprocess timeout and fixed executable/argv;
failed verification is not equivalent to detected malware.

## Uncertainty and reporting

A warning is a local policy decision, not a model claim of certainty. Limited
required evidence downgrades a concerning answer to uncertain warning. Missing
prerequisites yield unknown or not-applicable rule results. Process aggregation
prioritizes warning, uncertain warning and then unknown; unresolved dimensions
therefore prevent an unqualified probably-legitimate aggregate.

The summary's `incomplete` flag covers operational failures and selected-process
omissions. Coverage gaps and exited/changed processes have separate counters;
zero operational failures does not imply complete semantic knowledge. Explanatory
messages come from the local rubric and observed facts, not invented model prose.

## Cache and resource ownership

Cache identity hashes the exact canonical request and endpoint, so it includes
model, policy, shared state and bound questions. It expires quickly and never
learns an allowlist from repeated observations. Changing a process's PID/start
identity, age band, evidence or batch context changes the key. Responses are
stored; raw requests and process evidence are not.

A fixed worker pool consumes planned batches. The transport semaphore, pacing
lock and attempt budget include retries. Recognized context errors split batches
until a single target is reached. Errors there are explicit non-evaluations.
Authentication failures stop subsequent queued transport attempts. Concurrency
may leave already-started requests in flight; there is no claim of undoing them.

Read-only means no mutation of inspected processes or their software. The tool can
write its own cache and explicitly requested snapshots. Root/kernel compromise,
same-user tampering and provider compromise are outside its security boundary.

## References

- jevscan inspected at main commit `faf8ff66682fbaadb28eac9d244f61437a88b0b9`:
  `core/client.py`, `core/protocol.py`, `core/inference.py`, `cli/render.py`,
  `cli/terminal.py`, `pyproject.toml`, and contributor guidance.
- TypeSafe API: https://docs.typesafe.ai/api
- TypeSafe model capabilities: https://docs.typesafe.ai/models
- psutil process identity and platform limitations: https://psutil.readthedocs.io/

These contracts were reviewed on 2026-09-22. Real provider integration and native
macOS validation remain release gates, as recorded in VALIDATION.md.
