# Synthetic evaluation and calibration corpus

`jevproc-test` runs packaged, labeled process metadata through the same live Jev
client, request protocol, policy and assessment engine as `jevproc`. It never
executes corpus binaries, shell commands, payloads or network probes.

The corpus has **72 cases**:

- **30 benign / hard-negative controls** — system daemons, Homebrew services,
  compilers, shells from IDEs, package installers, unsigned local tools, temporary
  build artifacts, deleted updater binaries, VPN agents, browser helpers, backup
  tools and ordinary developer/network activity.
- **25 suspicious cases** — multi-signal combinations involving privilege/path
  mismatch, masquerading, user ownership under UID 0, world-writable executables,
  temporary/hidden locations, deleted images, failed signatures, unusual ancestry
  and synthetic network evidence.
- **10 ambiguous cases** — intentionally weak or dual-use patterns that are useful
  for the uncertain-warning boundary.
- **7 evidence-limited controls** — missing or partial executable/name/identity
  evidence that should remain unknown rather than being promoted to legitimate.

All addresses are IANA documentation/Test-Net values and command-line attack-like
content is represented only by inert descriptive markers.

## Regression mode

```sh
jevproc-test --list
jevproc-test
jevproc-test --case susp-root-user-writable-masquerade
jevproc-test --label benign
jevproc-test --format json
```

Regression mode compares jevproc's policy result with each case's declared accepted
statuses. Suspicious cases are considered successfully **surfaced** when they land
in either `warning` or `uncertain_warning`. Ambiguous cases are boundary probes:
they may legitimately land on either side of the alert boundary and therefore do
not fail regression merely for being benign-band versus review-band. Their raw
scores still participate in calibration analysis. Evidence-limited controls must
remain `unknown`. Exit codes are 0 when required expectations match, 1 for
classification mismatches, 2 for operational/config/provider failures, and 130
for Ctrl-C.

## Calibration mode

```sh
# Defaults to three independent live evaluations per selected case.
jevproc-test --calibrate

# More repeated samples when measuring model variance.
jevproc-test --calibrate --runs 5

# Full machine-readable case/sample statistics.
jevproc-test --calibrate --runs 5 --format json
```

The result cache is disabled, so every run reaches Jev. With the full 72-case
corpus, three runs mean **216 requests** before retries; five runs mean **360**.
Use the normal concurrency and provider limits when choosing a run count.

Calibration does not judge candidates through today's warning thresholds. It
extracts the raw JPR001 Noul value for every sample and reports:

- distribution statistics per ground-truth label: min, p05, p10, p25, median,
  p75, p90, p95, max, mean and standard deviation;
- case-mean separation, including the maximum benign mean and minimum ambiguous
  and suspicious means;
- repeated-run variance and the most unstable cases;
- how the **current** `uncertain_at / warning_at` pair performs on the corpus;
- explicit **suspicious surfaced recall** (warning or uncertain warning),
  suspicious hard-warning recall, benign surfaced rate, and benign hard-warning
  rate;
- descriptive candidate pairs:
  - **warnings first** — among pairs with zero benign hard warnings, maximize
    suspicious surfaced recall, then minimize benign surfaced alerts;
  - **balanced** — maximizes macro recall across benign / ambiguous / suspicious;
  - **zero benign FP** — prefers no benign case crossing the uncertain boundary;
  - **high suspicious recall** — targets at least 95% suspicious hard-warning
    recall when possible, then minimizes benign alerts.

The three-band calibration model is:

```text
score < uncertain_at                -> benign band
uncertain_at <= score < warning_at  -> ambiguous / uncertain band
score >= warning_at                 -> warning band
```

Evidence-limited `unknown` cases are summarized but excluded from threshold
optimization because their final status is deliberately constrained by missing
evidence rather than score alone.

Candidate thresholds are **descriptive synthetic-corpus operating points**.
`jevproc-test` never edits `jevproc.yaml`, packaged defaults or runtime policy.
The current packaged JPR001 defaults (`0.08 / 0.10`) were selected from the
warnings-first tradeoff observed on the synthetic corpus: tolerate a small review
band to surface weak suspicious signals while avoiding benign hard warnings. A
human should still review corpus composition, false-positive behavior and
repeated-run stability before future threshold changes.

## Why the corpus is deliberately difficult

Easy benign examples would make threshold calibration look artificially clean.
The benign set therefore includes cases that resemble common heuristic triggers:
unsigned user binaries, temporary build outputs, root package installation,
networked developer tools, user launch agents, deleted updater binaries and
third-party services. Conversely, suspicious examples generally combine multiple
independent signals rather than declaring one unusual path or unsigned binary
malicious by itself.

This is still a hand-designed synthetic corpus, not an independently sampled
malware/benign prevalence dataset. A clean separation is useful engineering
evidence, not a real-world detection-accuracy estimate.
