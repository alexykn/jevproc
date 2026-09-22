# 0.1.0rc1 validation record

Authoring date: **2026-09-22**. This file records the initial handoff, not future CI
or live-provider results. Passing software-contract tests is not evidence of a
validated malware detector.

## Executed locally

- **135 pytest cases passed** on Linux x86-64 / CPython **3.13.5**.
- Source and smoke-test scripts compiled successfully with `compileall`.
- Wheel and source distribution built successfully with **setuptools 82.0.1**
  through its PEP 517 build backend (`setuptools.build_meta`).
- The built wheel was installed into a separate virtual environment and exercised
  **outside the source checkout**, including package resources, module entry point,
  synthetic end-to-end JSON output and expected warning counts.
- The installed console entry point performed a real, local-only Linux process
  inventory with no command-line collection and zero Jev request attempts.
- Default, verbose, JSON and JSONL reports were exercised. Narrow terminal tests
  cover 20, 24, 40 and 80 columns, wide Unicode characters, control/bidi escaping
  and `NO_COLOR` precedence.

## Contracts covered

Collection checks cover missing permissions, exited processes, PID reuse,
executable-image path changes, parent chronology/cycles/depth, socket attribution,
protected command arguments, file replacement during optional inspection,
bounded regular-file hashing, and fixed-argv mocked macOS codesign execution.

Protocol and transport checks cover shared state and explicit target bindings,
exact answer IDs/types/labels/ranges, non-normalized distributions, malformed
responses, pinned-model mismatches, context splitting, single-target overflow,
HTTP retry and non-retry cases, Retry-After, request-attempt budgets, response-size
limits, decoded compression, bounded concurrency and safe error output.

Configuration and policy checks cover additive rulesets, round-trip packaged YAML,
patching built-ins, duplicate mapping keys, invalid limits, ignore rules, Noul /
Choice / Score thresholds, evidence downgrades, and the distinction between
ordinary unknown and uncertain warning. Storage checks cover TTL, cache identity,
corrupt answer invalidation, private file permissions, symlinks and exclusive writes.

## Environment qualification

Installed runtime dependencies used during testing:

| Package | Version |
| --- | --- |
| httpx | 0.28.1 |
| psutil | 7.2.2 |
| pydantic | 2.13.4 |
| PyYAML | 6.0.3 |
| wcwidth | 0.7.0 |
| pytest | 9.0.2 |
| pytest-asyncio | 1.3.0 |

The authoring container had these dependencies preinstalled. Its test and wheel
verification environments referenced those installed dependencies; the package
itself was installed separately for the wheel smoke test. **A clean online
resolver installation was not performed.** Package-index and developer-tool
downloads were unavailable. No `uv.lock` was invented or copied from another
project. Local environment shims are excluded from all deliverables.

The standard `python -m build` frontend was unavailable, so the equivalent
setuptools PEP 517 backend was invoked directly for local artifacts. CI uses the
normal build frontend after resolving its development environment.

## Not executed / remaining release gates

**Live Jev calls:** No credential was available and no real machine inventory was
sent to the provider. All HTTP integration tests use `httpx.MockTransport` and the
current documented wire contract. Verify authenticated live calls, actual usage
reporting and default model availability before relying on the integration.

**Native macOS and Python 3.12:** These could not run in the Linux/Python 3.13
container. macOS codesign behavior is mocked, not natively proven. The included
Linux/macOS × Python 3.12/3.13 CI matrix is prepared but **has not run remotely**.
Live Windows process collection is unsupported.

**Ruff, ty and Radon:** Tools were unavailable and download attempts failed. Their
local checks were not run and are not claimed as passing. Development dependencies
include them, but CI does not falsely assert an already-established lint/type gate.

**Security efficacy:** There is no labeled benign/malicious process corpus,
precision/recall estimate, false-positive rate, model-calibration result, adversarial
prompt-injection benchmark or sustained watch-mode soak test. The shipped values
are initial policy defaults, not security-certified thresholds. Run controlled
benign workloads and independently labeled incident evidence before promoting
this release beyond assisted triage. Do not execute live malware for testing.

**Publication:** No public GitHub repository, GitHub Release, remote CI run or PyPI
package was created. The source, package artifacts and a committed Git bundle are
the handoff. See PUBLISHING.md for the exact remaining GitHub publication step.
