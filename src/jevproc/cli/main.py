"""Compose collection, inference and reporting without hidden background work."""

import argparse
import asyncio
import os
import sqlite3
import sys
from contextlib import ExitStack
from typing import Any, Literal, TextIO

from pydantic import ValidationError

from jevproc.cli.args import parser
from jevproc.cli.render import Reporter, Terminal, render
from jevproc.core.client import JevClient
from jevproc.core.collector import CollectionError, collect, load_snapshot
from jevproc.core.config import Config, ConfigError, default_yaml, load_config
from jevproc.core.demo import demo_snapshot, demo_transport
from jevproc.core.engine import Engine
from jevproc.core.models import Report, Snapshot
from jevproc.core.protocol import JevError
from jevproc.core.storage import AnswerCache, StorageError, default_cache_dir, write_private


def _apply_boolean_flags(
    args: argparse.Namespace,
    target: dict[str, Any],
    flags: tuple[tuple[str, str], ...],
    value: bool,
) -> None:
    target.update({key: value for flag, key in flags if getattr(args, flag)})


def _enable_collection_flags(args: argparse.Namespace, collection: dict[str, Any]) -> None:
    _apply_boolean_flags(
        args,
        collection,
        (("include_command_line", "command_line"), ("hashes", "hashes"), ("signatures", "signatures")),
        True,
    )


def _disable_collection_flags(args: argparse.Namespace, collection: dict[str, Any]) -> None:
    _apply_boolean_flags(
        args,
        collection,
        (
            ("no_command_line", "command_line"),
            ("no_hashes", "hashes"),
            ("no_signatures", "signatures"),
            ("no_resources", "resources"),
            ("no_connections", "connections"),
        ),
        False,
    )


def _present_overrides(args: argparse.Namespace, fields: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    values = ((key, getattr(args, attribute)) for attribute, key in fields)
    return {key: value for key, value in values if value is not None}


def _collection_limits(args: argparse.Namespace, collection: dict[str, Any]) -> None:
    collection.update(
        _present_overrides(args, (("max_processes", "max_processes"), ("collection_workers", "workers")))
    )


def _jev_overrides(args: argparse.Namespace, jev: dict[str, Any]) -> None:
    jev.update(_present_overrides(args, tuple((name, name) for name in ("model", "max_requests", "concurrency"))))
    jev.update({"requests_per_minute": 0} if args.demo else {})


def _settings(args: argparse.Namespace) -> Config:
    config = load_config(args.config)
    data = config.model_dump(mode="json")
    _enable_collection_flags(args, data["collection"])
    _disable_collection_flags(args, data["collection"])
    _collection_limits(args, data["collection"])
    _jev_overrides(args, data["jev"])
    data["ignore"] = list(set(data["ignore"] + args.ignore))
    data["cache"]["enabled"] = not any((args.no_cache, args.demo, args.offline))
    return Config.model_validate(data)


def _snapshot(args: argparse.Namespace, config: Config) -> Snapshot:
    if args.demo:
        return demo_snapshot()
    if args.input is not None:
        return load_snapshot(args.input, include_command_line=config.collection.command_line)
    return collect(config.collection, args.pid, family_pid=args.family)


def exit_code(report: Report, fail_on: str) -> int:
    outcomes = (
        (bool(report.summary["incomplete"]), 2),
        (bool(fail_on != "none" and report.summary["warnings"]), 1),
        (bool(fail_on == "any" and report.summary["uncertain_warnings"]), 1),
    )
    return next((code for matches, code in outcomes if matches), 0)


def _scan_mode(args: argparse.Namespace) -> Literal["live", "offline", "demo"]:
    return "demo" if args.demo else "offline" if args.offline else "live"


def _save_snapshot(args: argparse.Namespace, snapshot: Snapshot) -> None:
    if args.save_snapshot is not None:
        write_private(args.save_snapshot, (snapshot.model_dump_json(indent=2) + "\n").encode())


async def _rendered_scan(
    args: argparse.Namespace,
    config: Config,
    engine: Engine,
    snapshot: Snapshot,
    stdout: TextIO,
) -> Report:
    mode = _scan_mode(args)
    if args.format == "json":
        report = await engine.scan(snapshot, mode=mode)
        render(report, stdout, verbose=args.verbose, format_name=args.format, width=args.width, color=args.color)
        return report

    reporter = Reporter(
        stdout,
        mode=mode,
        snapshot_time=snapshot.captured_at,
        model_requested=config.jev.model,
        synthetic=snapshot.synthetic or mode == "demo",
        total_processes=len(snapshot.processes),
        verbose=args.verbose,
        format_name=args.format,
        width=args.width,
        color=args.color,
    )
    report = await engine.scan(snapshot, mode=mode, on_assessment=reporter.emit)
    reporter.finish(report)
    return report


async def _scan_cycle(
    args: argparse.Namespace,
    config: Config,
    engine: Engine,
    stdout: TextIO,
) -> Report:
    snapshot = _snapshot(args, config)
    _save_snapshot(args, snapshot)
    return await _rendered_scan(args, config, engine, snapshot, stdout)


def _stop_watching(args: argparse.Namespace, report: Report) -> bool:
    return any((args.watch is None, bool(report.summary["incomplete"])))


async def _cycles(args: argparse.Namespace, config: Config, engine: Engine, stdout: TextIO) -> int:
    code = 0
    while True:
        report = await _scan_cycle(args, config, engine, stdout)
        code = max(code, exit_code(report, args.fail_on))
        if _stop_watching(args, report):
            return code
        await asyncio.sleep(args.watch)

def _live_api_key(args: argparse.Namespace) -> str:
    return "synthetic-demo-key" if args.demo else os.environ.get("TYPESAFE_API_KEY", "")


def _live_origin(args: argparse.Namespace) -> str:
    return "https://api.typesafe.ai" if args.demo else os.environ.get(
        "TYPESAFE_BASE_URL", "https://api.typesafe.ai"
    )


def _live_notice(args: argparse.Namespace, stderr: TextIO) -> None:
    if args.demo:
        return
    Terminal(stderr, color=args.color, width=args.width).line(
        "Live mode sends sanitized process metadata to the configured TypeSafe endpoint. "
        "Target environments and memory are not read; binary contents are never submitted. "
        "Use --offline for local inventory.",
        style="\x1b[2m",
    )


def _answer_cache(args: argparse.Namespace, config: Config, stack: ExitStack) -> AnswerCache | None:
    if not config.cache.enabled:
        return None
    return stack.enter_context(AnswerCache(args.cache_dir or default_cache_dir(), config.cache))


async def _run(args: argparse.Namespace, config: Config, stdout: TextIO, stderr: TextIO) -> int:
    if args.offline:
        return await _cycles(args, config, Engine(config), stdout)

    async with JevClient(
        config.jev,
        _live_api_key(args),
        base_url=_live_origin(args),
        transport=demo_transport() if args.demo else None,
    ) as client:
        _live_notice(args, stderr)
        with ExitStack() as stack:
            cache = _answer_cache(args, config, stack)
            return await _cycles(args, config, Engine(config, client, cache), stdout)

def _conflict(active: object, conflicts: tuple[object, ...], message: str) -> str | None:
    return message if active and any(conflicts) else None


def _watch_error(args: argparse.Namespace) -> str | None:
    return _conflict(
        args.watch,
        (args.demo, args.input, args.save_snapshot, args.format == "json"),
        "--watch requires live collection, text/jsonl output, and no --save-snapshot",
    )


def _demo_error(args: argparse.Namespace) -> str | None:
    return _conflict(
        args.demo,
        (args.input, args.pid, args.family, args.save_snapshot),
        "--demo cannot be combined with --input, --pid, --family or --save-snapshot",
    )


def _input_error(args: argparse.Namespace) -> str | None:
    return _conflict(args.input, (args.pid, args.family), "--pid/--family cannot be combined with --input")


def _validate_args(p: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    validators = (_watch_error, _demo_error, _input_error)
    message = next(filter(None, (validate(args) for validate in validators)), None)
    if message is not None:
        p.error(message)

def _safe_error(message: str) -> int:
    Terminal(sys.stderr, color="never").line(message)
    return 2


def _execute(args: argparse.Namespace) -> int:
    config = _settings(args)
    return asyncio.run(_run(args, config, sys.stdout, sys.stderr))


def _configuration_failure(exc: BaseException) -> int:
    return _safe_error(f"jevproc: {exc}")


def _operation_failure(exc: BaseException) -> int:
    return _safe_error(f"jevproc: operation failed ({type(exc).__name__}); no clean result is implied")


def _worker_failure(exc: BaseException) -> int:
    return _safe_error(f"jevproc: worker failed ({type(exc).__name__}); scan incomplete")


_FAILURE_HANDLERS = (
    ((KeyboardInterrupt,), lambda _exc: 130),
    ((BrokenPipeError,), lambda _exc: 0),
    ((ConfigError, CollectionError, StorageError, JevError), _configuration_failure),
    ((OSError, sqlite3.Error, ValidationError, UnicodeError), _operation_failure),
    ((ExceptionGroup,), _worker_failure),
)


def _known_failure(exc: BaseException) -> int | None:
    handler = next((handler for types, handler in _FAILURE_HANDLERS if isinstance(exc, types)), None)
    return handler(exc) if handler is not None else None


def _guarded_execute(args: argparse.Namespace) -> int:
    try:
        return _execute(args)
    except BaseException as exc:
        code = _known_failure(exc)
        if code is None:
            raise
        return code


def main(argv: list[str] | None = None) -> int:
    p = parser()
    args = p.parse_args(argv)
    if args.print_default_config:
        sys.stdout.write(default_yaml())
        return 0
    _validate_args(p, args)
    return _guarded_execute(args)
