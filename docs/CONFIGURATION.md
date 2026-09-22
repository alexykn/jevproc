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
  concurrency: 4
  requests_per_minute: 60
  max_requests: 200
collection:
  command_line: false
cache:
  ttl_seconds: 30
ignore: [JPR005]
rulesets:
  process:
    - id: JPR001
      policy:
        warning_at: 0.90
        confidence_min: 0.80
```

The `process` override patches JPR001 by ID and preserves the other built-ins.
An empty list does not erase a built-in ruleset. `ignore` accepts rule IDs or
ruleset names. Disabling every rule is rejected; use `--offline` for inventory.
CLI `--ignore` entries add to the config. Other explicitly supplied CLI overrides
win over the corresponding file values.

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
`"true"` and `"false"` keys. The answer is a scalar in [0,1]. No confidence field
is synthesized. The default warning/uncertain thresholds are 0.85/0.60. Near-middle
values that do not meet the uncertain-warning threshold remain ordinary unknown.

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

All requests share a semaphore, rate limiter and hard attempt budget. Retries and
context-recovery requests are charged too. Watch uses the same client and budget
throughout the invocation; Ctrl-C stops it. A cycle's delay begins after its report,
so `--watch 30` is not an exact 30-second sampling frequency.

`max_request_bytes` limits the entire encoded request. `max_state_question_bytes`
limits the shared state plus the longest single question. They are conservative
engineering guards, not a tokenizer or guaranteed context-fit calculation.
Oversized processes are never silently discarded or semantically truncated to fit.

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
