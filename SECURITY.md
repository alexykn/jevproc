# Security boundaries

`jevproc` is read-only, model-assisted **triage**, not protection against an active
attacker and not a source of verified malware labels. Never automatically kill,
quarantine, block network access or delete files based on its output.

## Data handling

Live mode submits sanitized process metadata to TypeSafe, or to the explicitly
configured `TYPESAFE_BASE_URL`. By default this includes process paths, redacted
command arguments, socket endpoints, bounded executable hashes, file metadata and
macOS signature identity where available. Environment variables of inspected
processes and process memory are never read. Hashing reads bounded executable
bytes locally but sends only the hash; no binary or script contents are submitted.
The API key is used only for transport
headers; it is not included in logs, request bodies, snapshots or cache keys.

Redaction recognizes common credential flags, authorization strings, URL userinfo,
well-known token formats and home-directory usernames. It is best effort and can
miss arbitrary positional secrets, novel formats, secrets in names or paths, and
sensitive business information. Use `--no-command-line` or a stricter explicit
configuration on workloads that prohibit argument disclosure. `--offline` avoids
the external API entirely; `--no-connections` alone does not.

Saved snapshots are new, exclusive 0600 files. Existing paths are not overwritten.
Redirected stdout reports follow the shell's umask and can be less private. The
cache uses a private 0700 directory and 0600 database and stores structured answers,
not evidence. Use a cache directory under your own trusted home directory; do not
select an attacker-controlled parent path, especially when elevated.

## Untrusted evidence

Names, paths, arguments, observations, socket values and imported snapshots may
be attacker-controlled. They are data, not instructions. Terminal control and
bidirectional characters are escaped. Imported JSON and provider responses are
bounded and schema-validated. The model is told to ignore embedded instructions,
but this is not a demonstrated defense against all prompt-injection attacks.

Process ancestry is not an event log. Signatures and hashes describe disk evidence,
not running memory. No reputation database or trust allowlist is consulted. A
malicious invocation of a legitimate interpreter can look normal in a metadata-only
snapshot. A short-lived process may not be observed at all. A compromised OS can
forge every observation on which this program depends.

## Operational behavior

The collector does not terminate, suspend, attach to or alter processes. Inspection
subprocesses are fixed-path macOS `codesign` calls and, when psutil socket
enumeration is denied on macOS, fixed-path `lsof`; both use explicit argv, no
shell and bounded timeouts. Target executables are never run.
Retries, rate pacing and request-attempt budgets are bounded. Context failures
are reported without splitting the snapshot.
HTTP errors, bad answers and budget exhaustion do not produce benign results.

Filesystem calls and process enumeration are still OS operations: a stalled mount
or unresponsive kernel can delay them. Per-request timeouts and per-file byte limits
are not a guarantee of a hard wall-clock deadline for the whole scan.

## Reporting defects

Report reproducible code or privacy bugs without uploading real credentials,
private process inventories or live malware. Prefer minimal synthetic snapshots
and mocked responses. A public repository's private vulnerability-reporting
feature must be enabled by its owner before relying on that channel; this handoff
does not configure repository settings or create a reporting address.
