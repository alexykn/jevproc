"""CLI inputs; explicit opt-in for sensitive or expensive collection."""

import argparse
import math
from pathlib import Path

from jevproc import __version__


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def interval(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number < 1:
        raise argparse.ArgumentTypeError("watch interval must be finite and at least 1 second")
    return number


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jevproc", description="Read-only process triage with Jev. Warnings and uncertain warnings are shown by default.")
    p.add_argument("--version", action="version", version=f"jevproc {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="show all processes and all rule results")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--offline", action="store_true", help="inventory only; do not contact Jev or classify processes")
    mode.add_argument("--demo", action="store_true", help="run clearly labeled synthetic fixtures; no API key or live collection")
    target = p.add_mutually_exclusive_group()
    target.add_argument("--pid", type=positive_int, action="append", help="inspect only a PID (repeatable)")
    target.add_argument("--family", type=positive_int, metavar="PID", help="inspect a PID and its descendant process family")
    p.add_argument("--input", type=Path, help="evaluate a saved, schema-validated snapshot instead of collecting")
    p.add_argument("--save-snapshot", type=Path, help="save sanitized metadata to a new 0600 file; never overwrite")
    p.add_argument("--include-command-line", action="store_true", help="collect and submit redacted command arguments (enabled by default)")
    p.add_argument("--no-command-line", action="store_true", help="omit command arguments from collection and Jev requests")
    p.add_argument("--no-connections", action="store_true", help="do not collect sockets (does not disable the Jev API)")
    p.add_argument("--hashes", action="store_true", help="hash bounded regular executable files (enabled by default)")
    p.add_argument("--no-hashes", action="store_true", help="skip executable SHA-256 hashing")
    p.add_argument("--signatures", action="store_true", help="inspect on-disk macOS signatures (enabled by default)")
    p.add_argument("--no-signatures", action="store_true", help="skip macOS code-signature inspection")
    p.add_argument("--no-resources", action="store_true", help="skip CPU/memory/thread/fd evidence")
    p.add_argument("--config", type=Path, help="explicit YAML overrides; no implicit current-directory config discovery")
    p.add_argument("--print-default-config", action="store_true", help="print the packaged YAML and exit")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE_OR_SET", help="disable a rule/ruleset (repeatable)")
    p.add_argument("--model", help="Jev model ID; a pinned version is preferred")
    p.add_argument("--max-processes", type=positive_int, help="bound the process inventory; omissions are reported")
    p.add_argument("--collection-workers", type=positive_int, help="maximum concurrent local evidence-collection workers")
    p.add_argument("--max-requests", type=positive_int, help="hard attempt budget including retries across watch cycles")
    p.add_argument("--concurrency", type=positive_int, help="maximum concurrent per-process Jev requests")
    p.add_argument("--no-cache", action="store_true", help="disable the local short-lived answer cache")
    p.add_argument("--cache-dir", type=Path, help="private cache directory (must be owned and mode 0700)")
    p.add_argument("--watch", type=interval, metavar="SECONDS", help="repeat snapshots after this delay; append reports without clearing the screen")
    p.add_argument("--format", choices=["text", "json", "jsonl"], default="text", help="JSON formats always include all processes")
    p.add_argument("--width", type=positive_int, help="terminal width (minimum 20 columns)")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    p.add_argument("--fail-on", choices=["warning", "any", "none"], default="warning",
                   help="exit 1 for warnings (default), any finding, or never; operational failures still exit 2")
    return p
