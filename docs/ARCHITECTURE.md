# Architecture and contracts

```text
psutil snapshot or validated saved JSON
  -> privacy minimization + bounded typed Process records
  -> independent rule applicability checks
  -> one Jev request per selected process
  -> validated cache / paced Jev client
  -> exact typed answers
  -> local warning policy
  -> progressive assessment events
  -> warnings-first text OR complete versioned JSON/JSONL
```

`core/models.py` owns external snapshot and report records. `collector.py` owns
OS access, permission gaps, lifecycle checks and on-disk inspection. `privacy.py`
minimizes imported and collected data. `config.py` validates explicit operator
policy. `protocol.py` binds targets and owns response validation; `client.py`
handles only transport, pacing and request accounting. `assessment.py` applies
local policy. `engine.py` owns orchestration. `cli` never invents a second detector.

## One process, one request

Each selected process is evaluated independently. Its full compacted evidence is
placed once in `state.process`, and every applicable rule for that process is sent
as an independent question with an explicit target binding. This follows the same
state/question shape used successfully by jevscan while preventing a large process
table or hundreds of process questions from sharing one provider request.

A bounded worker pool schedules process requests. The transport semaphore and
shared limiter cap concurrency and, when configured, request starts. The default is
16 concurrent requests with no fixed local start-rate throttle; provider overload
responses drive backoff. This is scheduling, not semantic batching: a process is
never split across requests and two processes never share one request.

Cache identity is per process request, so unchanged processes can be reused even
when another process changes. Provider context or request-validation failures are
also process-local and do not erase successful classifications for other
processes.


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

## Progressive reporting

The engine accepts an assessment callback and invokes it synchronously on the
event loop as soon as each process worker completes. The final `Report` remains
the authoritative complete, PID-sorted result, but interactive text does not wait
for that object before showing findings.

The CLI constructs its reporter before inference. Text reporters immediately
flush visible warnings/uncertain warnings (or every process under `--verbose`)
and maintain one carriage-return progress line on TTYs. JSONL emits one process
event per completed assessment. JSON intentionally stays buffered until completion
so it remains one conventional report document.

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
At most the configured number of process requests are in flight. Authentication, transport
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
