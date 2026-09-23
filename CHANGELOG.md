# Changelog

## Unreleased

- Finish the maintainability pass by simplifying provider error traversal, top-level collection orchestration, argv redaction state, codesign/file inspection phases, and cache-file lifecycle.
- Roll back only newly-created cache files when validation fails; never delete a pre-existing invalid cache file.


- Separate evidence backends from parallel collection orchestration.
- Separate synthetic experiment execution/accounting from corpus CLI rendering.
- Clarify answer-type policy dispatch, configuration merging, redaction, and transport retry paths.
- Close SQLite connections if cache initialization fails before ownership transfer.

- Remove the local evidence-gathering progress line now that parallel collection completes fast enough to make it flicker.


- Replace serial PID evidence collection with a bounded parallel local worker pool.
- Deduplicate executable paths before parallel hash/signature inspection and overlap file, socket and child-table collection.
- Parallelize post-socket PID/executable revalidation while preserving identity ordering guarantees.
- Use psutil `oneshot()` for grouped process reads and add `--collection-workers` tuning.


- Distinguish legacy macOS resource-envelope signatures and unsigned code from generic `codesign` verification failures.
- Normalize common `codesign` failure reasons and retain signer metadata when display information remains readable.


- Recalibrate JPR001 to `uncertain_at=0.08` / `warning_at=0.12` after adding resource/child evidence.
- Select operational calibration candidates from individual repeated-run samples instead of case means.
- Report sample-level separation and keep case-mean candidate metrics as a separate stability view.
- Restore JPR001's concise pre-resource instruction text; richer evidence remains in state without prompt over-specification.

- Add CPU/RSS/memory/thread/FD context and bounded direct-child summaries to Jev process evidence without adding them to text output.
- Resolve parent context for single-PID checks and add `--family PID` for root-plus-descendant evaluation.
- Update the 72-case calibration corpus with non-correlated resource profiles and benign/suspicious child-process examples.

- Enable redacted command lines, bounded executable hashes and macOS signature inspection by default.
- Deduplicate expensive hash/signature work per stable file identity and include bounded signer metadata.
- Fall back to partial numeric `lsof` socket collection on macOS when psutil system-wide enumeration is denied.
- Enrich the 72-case calibration corpus to match the richer default evidence profile.

- Calibrate JPR001 defaults to `uncertain_at=0.08` and `warning_at=0.10` from the 72-case synthetic corpus.
- Simplify Noul policy mapping to direct benign/review/warning bands and remove inverse-threshold symmetry.
- Track suspicious surfaced recall separately from hard-warning recall and benign hard-warning false positives.
- Treat suspicious corpus cases as passing when surfaced and ambiguous cases as non-failing boundary probes.

- Expand the synthetic process corpus to 72 labeled benign/suspicious/ambiguous/evidence-limited cases.
- Add repeated-run raw-Noul calibration with quantiles, stability analysis and descriptive threshold-pair candidates.

- Add a packaged synthetic warning/benign/unknown evaluation corpus and `jevproc-test` live regression command.

- Stream completed process assessments to text and JSONL output instead of waiting for the full scan.
- Show one in-place TTY progress line between streamed findings.

- Evaluate each process in its own Jev request, with every applicable rule for that process in the same call.
- Restore bounded concurrency/rate pacing without reintroducing multi-process batching.
- Align the request state/question contract with jevscan and make cache/failures process-local.
- Surface safe structured metadata for HTTP 400/422 provider rejections.

- Evaluate the selected process snapshot in one Jev request instead of fixed four-process batches.
- Compact the inference wire and move per-process evidence into independent questions, matching Jev 1.13 context semantics.
- Replace the five built-in dimensions with one default process-risk Noul; custom rules remain supported.
- Remove batching, worker-pool, concurrency and byte-budget configuration.


## 0.1.0rc1 — 2026-09-22

Initial integration release candidate:

- Read-only Linux/macOS process inventory; explicit coverage and process-instance checks.
- Five packaged Choice/Noul rules, custom Score support, shared-state Jev requests.
- Warning and uncertain-warning default view; verbose details and complete JSON/JSONL.
- Opt-in command arguments, hashes and macOS signature checks; best-effort redaction.
- Bounded batching, retry/rate handling, invocation-wide request budget and private TTL cache.
- Local-only inventory, protected snapshot export/import and append-only watch reports.
- Synthetic end-to-end demo, regression suite, packaging and CI workflow.

No real-world detection accuracy, native macOS pass, live-provider pass, remote CI
success, PyPI publication or public GitHub repository creation is claimed by this
handoff. See docs/VALIDATION.md and docs/PUBLISHING.md.
