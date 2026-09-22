# Synthetic evaluation corpus

`jevproc-test` runs a packaged, labeled process-metadata corpus through the same
live Jev client, request protocol, policy and assessment engine as `jevproc`.
It does **not** execute malware, corpus binaries, shell commands or network probes.

The corpus exists to answer a narrower regression question: does the current
model + rubric still classify deliberately strong suspicious evidence as a
warning, preserve an ambiguous case as warning/uncertain-warning, keep a benign
control below warning, and refuse to call missing evidence legitimate?

## Run it

```sh
# Show cases without contacting Jev.
jevproc-test --list

# Run the whole corpus against live Jev. Uses TYPESAFE_API_KEY.
jevproc-test

# Run selected cases.
jevproc-test --case root-user-writable-masquerade
jevproc-test --case temporary-dropper-with-network --case benign-build-tool

# Machine-readable output.
jevproc-test --format json
jevproc-test --format jsonl
```

Exit codes are 0 when every case matches its declared accepted statuses, 1 for
classification mismatches, 2 for operational/config/provider failures, and 130
for Ctrl-C. Results stream as cases finish in text and JSONL modes.

The packaged cases currently include four exact-warning positives, one ambiguous
warning-or-uncertain case, one benign build-tool control, and one deliberately
evidence-starved unknown control. Exact accepted statuses live beside each case
in `src/jevproc/data/test-corpus.json`, so a changed expectation is reviewable
policy rather than hidden test logic.

## Safety and interpretation

Every process is synthetic metadata. Network endpoints use IANA documentation
ranges (TEST-NET); command lines contain inert placeholders where a real attack
would contain executable content. The runner never creates the named paths,
connects to the listed endpoints, launches the listed commands or mutates the
host.

A corpus pass is **not** a malware-detection accuracy claim. These are small,
hand-designed regression cases rather than an independently labeled prevalence
sample. Model updates can legitimately move borderline scores, which is why the
ambiguous case accepts either `warning` or `uncertain_warning`. Exact-warning
cases are intentionally stronger and should be investigated if they stop crossing
the configured warning threshold.

Use `--config`, `--model` and `--concurrency` to evaluate policy/model changes
against the same evidence. The runner disables the result cache so each invocation
actually reaches Jev.
