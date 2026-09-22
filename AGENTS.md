# Contributor guidance

Keep the `src/jevproc/{core,cli}` split. Core owns collection, protocol contracts,
assessment and resource accounting; CLI owns arguments and presentation. Prefer
small, cohesive functions, explicit data flow and readable error paths.

Never add Rich or another terminal UI framework. Default text shows warnings and
uncertain warnings only. Ordinary unknowns are verbose-only, but operational errors
and coverage accounting must remain visible. JSON/JSONL must stay complete.

Treat every process field, imported snapshot and provider answer as untrusted at
its boundary. Do not run target executables, inspect target environments/memory,
add telemetry or automate remediation. Sensitive collection must remain explicit.
Do not turn missing evidence into either malware evidence or a safety guarantee.

Keep shared state separate from explicit target-bound question instructions.
Question dictionary keys alone do not bind a model target. Preserve Jev numeric
values; Noul has no confidence, and distributions are not normalized. Changes to
policy and state representation must invalidate cache identity and get focused tests.

Use uv, Python 3.12+, pyproject.toml and a local .venv. Tests must run without real
API keys and must never submit a developer's process list. Keep fixtures obviously
synthetic. Run pytest and wheel/resource smoke tests after changes; run Ruff, ty
and Radon when available and report their actual results, not assumptions.

Report verification honestly. Passing contract tests does not calibrate detection
accuracy. Keep VALIDATION.md up to date; do not label a live-provider, platform or CI
check successful without executing it. Do not introduce a lockfile that was not
resolved and checked. Never commit .env files, real snapshots, API keys or caches.
