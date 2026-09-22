# Changelog

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
