# Architecture and contracts

```text
psutil snapshot or validated saved JSON
  -> privacy minimization + bounded typed Process records
  -> independent rule applicability checks
  -> one Jev request for the complete selected snapshot
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

## One snapshot, one request

The shared `state` contains host context, the fixed evidence policy, active rule
definitions and compact field legends. It deliberately does **not** repeat the
whole process table. Each independent question carries one compact process record
and explicitly names its target and rule. The provider's API says question IDs
are not passed to the model, so the target binding remains inside instructions.
The full local `Process` objects are retained for reporting and policy decisions;
only the inference wire is compacted.

This layout follows Jev 1.13's documented context model: 64k tokens for a full
request, with a 32k limit on shared state plus the longest question. It also
follows TypeSafe's speculative fan-out guidance that many independent questions
should normally be sent together because they are evaluated in parallel. There
is no process batch planner, API worker pool, recursive context split or local
byte-count approximation of model tokens. If the provider rejects an unusually
large snapshot, every affected process is explicitly `not_evaluated`; the tool
does not silently change the context and retry subsets.

Question independence is intentional. Relationships between observed processes
are evidence only when present in the process record; they are not fabricated
execution history. There is no hidden agent/tool loop, shell execution or
model-written remediation.

The boundary checks exact answer IDs, answer types, criterion labels, finite
ranges and score scale. Choice/Score numeric distributions are preserved without
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
identity, age band, evidence or snapshot context changes the key. Responses are
stored; raw requests and process evidence are not.

The transport pacing lock and attempt budget include retries and watch cycles.
A snapshot has only one in-flight evaluation request. Authentication, transport
and context failures become explicit non-evaluations rather than fallback
classifications.

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
