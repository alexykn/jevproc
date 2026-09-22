# Configuration

Use `--print-default-config` for the complete schema-backed default. Only an
explicit `--config PATH` is loaded; there is no implicit `./jevproc.yaml` lookup.
A selected file is trusted operator policy, not an untrusted scan target.

A minimal override:

```yaml
host_context: >-
  Linux build worker. Compiler subprocesses and temporary build executables are
  expected. Interactive logins should be rare. These expectations are context,
  not an automatic allowlist or evidence that an invocation was authorized.
jev:
  concurrency: 8
  requests_per_minute: 0
  max_requests: 200
collection:
  command_line: false
cache:
  ttl_seconds: 30
ignore: []
rulesets:
  process:
    - id: JPR001
      policy:
        warning_at: 0.90
```

The `process` override patches the built-in JPR001 classifier by ID. An empty
list does not erase a built-in ruleset. `ignore` accepts rule IDs or ruleset
names. Disabling every rule is rejected; use `--offline` for inventory.
CLI `--ignore` entries add to the config. Other explicitly supplied CLI overrides
win over the corresponding file values.

## Collection defaults

The default collector is evidence-rich:

```yaml
collection:
  connections: true
  command_line: true
  hashes: true
  signatures: true
  resources: true
  resource_sample_seconds: 0.10
  child_limit: 16
```

Resource evidence is a short shared sampling window, not a profiler: CPU percent,
RSS, memory percent, thread count and file-descriptor count are collected when
available. Direct children are summarized with bounded PID/name/path/status context;
`child_limit` caps the submitted list while preserving the observed total count.
High resource use or many children are explicitly not treated as malicious by
themselves.

`--pid PID` evaluates only that selected process while still resolving its parent
chain and bounded direct children for context. `--family PID` evaluates the root
PID plus all currently observed descendants, bounded by `max_processes`.

Command arguments are bounded and redacted before submission. Hashing reads only
bounded regular executable files and sends the SHA-256, never file contents.
macOS signature inspection sends verification status plus bounded identifier,
team-ID and authority metadata. Hash/signature work is deduplicated by stable
on-disk file identity within each snapshot.

On macOS, system-wide psutil socket enumeration can be denied to an unprivileged
process. In that case jevproc falls back to fixed-path `/usr/sbin/lsof` and marks
the resulting socket coverage `partial`. Use `--no-command-line`,
`--no-connections`, `--no-hashes` or `--no-signatures` when a lighter
collection profile is explicitly desired.

## Adding questions

```yaml
rulesets:
  local:
    - id: LOCAL001
      title: Unexpected administrative invocation
      message: Compare this invocation with the host's administrative policy.
      requires: [command_line, ancestry]
      question:
        type: noul
        instructions: >-
          Does the supplied invocation and available ancestry provide concrete
          evidence of unauthorized administrative execution under host_context?
          Do not infer authorization or wrongdoing solely from the use of sudo,
          root privileges, SSH, or a shell. Missing context is unknown.
      policy:
        warning_at: 0.90
        uncertain_at: 0.65
```

Question instructions are wrapped with the fixed evidence policy and explicit
process-instance target. They do not replace the injection-defense policy.
That policy reduces ambiguity; it does not prove resistance to prompt injection.

`requires` supports `executable`, `command_line`, `connections`, `ancestry`,
`file`, `signature`, and `hash`. Unavailable or unrequested sources skip the
question locally. Partially collected evidence may be sent, but a corresponding
finding cannot become a full warning. An empty observed socket list is not
historical proof of no network activity.

### Noul

Use `type: noul` and an atomic yes/no question. Optional criteria must have quoted
`"true"` and `"false"` keys. The answer is a scalar in [0,1]. No confidence field is synthesized. The default
JPR001 thresholds are calibrated to the packaged synthetic corpus at
`uncertain_at: 0.08` and `warning_at: 0.12`. For Noul rules, complete evidence
maps directly into three bands: below `uncertain_at` is
`probably_legitimate`, the review band is `uncertain_warning`, and values at or
above `warning_at` are `warning`. Evidence-limited cases are never promoted to
a confident warning/legitimate result solely from the scalar.

### Choice

Use `type: choice` with a mapping of label to criterion. The policy must specify
`warning_choices`; `legitimate_choices` is optional and disjoint. A warning needs
a selected warning label, selected-label support above `warning_at`, confidence
above `confidence_min`, and sufficient declared evidence. A selected warning label
or another warning label above `uncertain_at` produces an uncertain warning.
Risk support is the **maximum** warning-label value, not a sum of possibly
non-normalized values. Conflicting or weak legitimate answers remain unknown.

### Score

Use `type: score` with a list of 2–10 ordered criteria, increasing in concern.
`score_warning_at` and `score_uncertain_at` refer to that scale, not the probability
thresholds. Scores may be fractional. Set thresholds inside the chosen scale.
High concern with low confidence is an uncertain warning. A low-confidence score
below that threshold remains ordinary unknown.

## Limits and cache

Each selected process produces one Jev request containing all applicable questions
for that process. Requests are scheduled concurrently and bounded by
`jev.concurrency` (16 by default). `jev.requests_per_minute: 0` disables proactive
local pacing; provider `429`/`529` responses trigger backoff. Set a positive value
only when you explicitly want a local start-rate cap. Retries and watch cycles
share the hard `max_requests` attempt budget.

A provider context rejection affects only that process request. Generic 400/422
rejections expose only bounded machine-readable fields and the provider request ID;
response prose is never printed. The cache is also per process request, so an
unchanged process can hit cache independently of the rest of the snapshot.


`TYPESAFE_BASE_URL` is an explicit transport-origin override. It requires HTTPS
except loopback test servers and rejects embedded credentials, paths, queries and
fragments. HTTP redirects and environment-provided HTTP proxies are not followed.
Changing this origin changes who receives the API key and metadata; use only a
trusted endpoint. The API key itself is not accepted in YAML.

The cache directory defaults to `$XDG_CACHE_HOME/jevproc` when that variable is
absolute, otherwise `~/.cache/jevproc`. The leaf directory must be private and
owned (0700); the database must be private, regular and owned (0600). Cache writes
are transactional and corrupted answer records are invalidated. Unreadable or
corrupt database structures are operational failures, not successful empty scans.
