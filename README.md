# jevproc

**Warnings-first process triage with Jev. Plain terminal output. No Rich.**

`jevproc` takes a read-only Linux or macOS process snapshot, sends bounded,
privacy-minimized evidence to Jev, and applies a local warning policy to its
structured answers. It is a sibling project to [jevscan](https://github.com/alexykn/jevscan),
not an antivirus engine, an EDR agent, or a replacement for incident response.

The default text report shows **warnings and uncertain warnings only**. Use
`-v` / `--verbose` to include other processes and all rule results. Missing
permissions alone are ordinary uncertainty, not a warning. Operational failures
and coverage counts remain visible even when process rows are hidden.

**Status: 0.1.0rc1, integration release candidate.** Tests exercise the collector,
protocol and policies; they do not establish real-world detection accuracy.
The default rubric has not been calibrated against a labeled process corpus.
See [validation](docs/VALIDATION.md) for exactly what has and has not been checked.

## Install and try it

Python 3.12 or later is required. From this source checkout:

```sh
uv sync
uv run jevproc --demo --fail-on none
```

The demo uses packaged synthetic snapshots and answers through the real request,
validation, assessment and rendering pipeline. It makes no external API calls,
does not inspect your machine, and is clearly labeled. It is not a malware test.

For a standalone command, install from the checkout or the supplied wheel:

```sh
uv tool install .
# Alternatively: uv tool install ./jevproc-0.1.0rc1-py3-none-any.whl
jevproc --help
```

This initial handoff is not a PyPI publication. Do not assume `uv tool install
jevproc` downloads this project. A dependency lockfile is not included; see the
validation notes before claiming a fully reproducible environment.

## Live triage

Set `TYPESAFE_API_KEY` in your environment using your normal secret-management
workflow. `jevproc` never loads a `.env` file automatically.

```sh
jevproc                         # Warnings and uncertain warnings only
jevproc -v                      # Every process, all checks, available metadata
jevproc --pid 1234 --pid 1235     # Selected processes; repeat --pid as needed
jevproc --include-command-line  # Explicitly collect and submit redacted arguments
jevproc --hashes --signatures   # Optional on-disk SHA-256 and macOS codesign checks
jevproc --watch 30 --max-requests 200
jevproc --format json
jevproc --format jsonl --watch 30
```

Live mode sends process names, paths, UID, parent context, file metadata and
available socket endpoints to the configured TypeSafe API. Arguments are excluded
unless enabled by the flag or an explicitly selected config file. Home-directory
usernames and recognizable credentials are redacted on a best-effort basis.
**Metadata and internal IP addresses can still be sensitive.** Review your
organization's data-handling requirements before using live mode.

Do not run as root merely to make coverage counts disappear. Start with your
normal account. macOS and restricted Linux environments may deny process or
socket access. The tool reports this rather than claiming a clean result.

`--signatures` uses `/usr/bin/codesign --verify --strict` only on macOS; elsewhere
its coverage is unavailable. Valid signatures are not a trusted-signer allowlist,
notarization result, or safety verdict. Hashes describe a bounded regular file on
disk, not the in-memory executable image. No inspected binary is ever executed.

### Local-only inventory and saved snapshots

```sh
jevproc --offline -v
jevproc --offline --no-connections --save-snapshot snapshot-local.json
jevproc --offline --input snapshot-local.json -v
jevproc --input snapshot-local.json
```

`--offline` performs **inventory only**, never semantic classification or external
API calls. `--no-connections` disables socket collection, **not** the Jev API.
Snapshot saving is exclusive, mode 0600, and refuses existing files or symlinks.
Command-line collection policy is reapplied when importing a snapshot. Enabling
it during import cannot recover arguments that were never saved.

Imported snapshots are evidence about their recorded time, not a current health
check. `--pid` limits collection and therefore also limits available ancestry;
parents outside the selected set are reported as missing context.

## Output

A shortened excerpt from the synthetic demo:

```text
  system-update  PID 4819  UID 1000
    /tmp/.session/update
    Parents: document-viewer (4801)
      ! JPR001  Process risk
        noul=0.950

  build-helper  PID 6120  UID 1000
    /tmp/build/helper
      ? JPR001  Process risk
        noul=0.650  [uncertain warning]
```

Text uses small ANSI styles with Unicode-cell-aware wrapping and hanging
indentation. Piped output is plain; `NO_COLOR` overrides forced color.
Process-supplied control characters and bidirectional controls are escaped.
There are no full-screen redraws, panels, terminal UI frameworks, or Rich dependency.

JSON and JSONL are complete, versioned reports regardless of `--verbose`. They
include all selected processes, coverage, the original numeric model answers,
local policy results and counters. Treat redirected reports as sensitive; shell
redirection permissions are controlled by **your shell**, not the program.

| Result | Default text | Meaning |
| --- | --- | --- |
| `warning` | Shown | The local policy threshold is met; investigate, do not auto-kill |
| `uncertain_warning` | Shown | A concerning answer exists but confidence/support/evidence is limited |
| `unknown` | Verbose only | The available evidence does not support a conclusion |
| `probably_legitimate` | Verbose only | A supported legitimate interpretation, not proof of safety |
| `no_warning` | Verbose only | The configured checks did not cross a warning threshold |
| `not_evaluated` | Verbose only | Offline, unstable identity, missing requirements or an operational failure |

Default exit codes are **0** for no policy-triggered warning, **1** for a warning,
**2** for configuration/transport/storage failures or an incomplete selected scan,
and **130** for Ctrl-C. `--fail-on any` also returns 1 for uncertain warnings;
`--fail-on none` does not suppress operational exit 2. Exit 0 is **not** a clean
bill of health. Exited/reused/changed processes are reported and skipped rather
than being interpreted as malicious or as transport failures.

## Built-in rule and Jev integration

The default classifier asks **one Noul question per process**: does this specific
process instance have concrete evidence of malicious or abusive behavior in the
observed snapshot? The local policy maps high probability to `warning`, the review
band to `uncertain_warning`, and sufficiently low probability with complete basic
evidence to `probably_legitimate`. This is triage, not a malware verdict. Custom
Choice, Score and additional Noul rules remain supported through YAML.

The transport follows the [TypeSafe API](https://docs.typesafe.ai/api): one
`POST /v1/systemone` per snapshot with a small shared `state` (host context,
policy, rubric and compact field legends) and one independent question per
process. Each question carries its own compact process evidence and explicit
target binding because question IDs are not used in inference. The full local
report still retains the richer process schema.

Jev 1.13 documents a 64k-token total request budget and a separate 32k-token
budget for `state` plus the single longest question. It ingests state once and
evaluates questions in parallel; TypeSafe recommends putting the questions a
system needs into one request. `jevproc` therefore does **not** implement process
batches, a worker pool, recursive splitting, or byte-based pseudo-token guards.
A provider context rejection makes the snapshot explicitly incomplete instead of
silently changing the context in which subsets of processes are judged. Use
`--pid` or reduce optional evidence if an unusually large snapshot exceeds the
provider limit.

Noul is one scalar, not a score plus invented confidence. Choice and Score retain
the provider's confidence and probability fields for custom rules. Values must be
finite, in range, and have exactly the required labels, but they are **not
normalized or rejected merely because their sum differs from one**, matching
jevscan's existing response contract. Model confidence is not severity or an
empirically calibrated malware probability.

The default model is pinned to `jev-1.13.0`; aliases are allowed but explicit
versioning is preferred. Retries and watch cycles share the hard request-attempt
budget. HTTP failures never become benign judgments.

## Configuration and development

```sh
jevproc --print-default-config > jevproc.yaml
jevproc --config jevproc.yaml
jevproc --ignore JPR005
```

Overrides are explicit, validated YAML. Named rulesets are additive; built-in rules
can be patched by ID without erasing other built-ins. Duplicate YAML mapping keys,
unknown settings, invalid thresholds, and unknown ignore IDs fail early. No
configuration is discovered implicitly in the working directory, especially when
running with elevated privileges. See [configuration](docs/CONFIGURATION.md).

The short-lived private SQLite cache stores structured answers, not raw evidence.
Its identity includes the exact request and endpoint. It is not a baseline,
allowlist or durable verdict. TTL defaults to 60 seconds; use `--no-cache` to
re-evaluate identical evidence. PID/start-time, model, prompt and evidence changes
invalidate reuse. There is no auto-learning trust baseline in this release.

```sh
uv sync
uv run pytest
uv run python -m compileall -q src
uv run python -m build
```

The project layout is `src/jevproc/{core,cli}`. CI runs the contract suite and an
installed-wheel smoke test on Linux and macOS with Python 3.12 and 3.13; it does
not use API keys. The initial handoff's remote CI has **not yet run**.
Ruff, ty and Radon are included as development tools; their initial local execution
was blocked by unavailable downloads. Their checks are not claimed as passing.

Read [architecture](docs/ARCHITECTURE.md), [security boundaries](SECURITY.md),
[validation](docs/VALIDATION.md), and [publishing](docs/PUBLISHING.md) before
promoting this integration candidate to a security-product release.

## Scope

This release does not provide event tracing, persistence discovery, loaded-module
inspection, file-content analysis, threat-intelligence lookups, a trusted signer
list, behavioral baselines, or automated remediation. A short-lived process can
start and exit between snapshots. Process metadata can be forged, snapshots are
not atomic, and a compromised kernel can lie to the collector. Absence of a warning
is not evidence that the machine is uncompromised.

MIT licensed. See [acknowledgments](ACKNOWLEDGMENTS.md).
# jevproc
