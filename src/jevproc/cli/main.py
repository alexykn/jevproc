"""Compose collection, inference and reporting without hidden background work."""

import argparse
import asyncio
import os
import sqlite3
import sys
from contextlib import ExitStack
from typing import Any, TextIO

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


def _enable_collection_flags(args: argparse.Namespace, collection: dict[str, Any]) -> None:
    for flag, key in (
        ("include_command_line", "command_line"),
        ("hashes", "hashes"),
        ("signatures", "signatures"),
    ):
        if getattr(args, flag):
            collection[key] = True


def _disable_collection_flags(args: argparse.Namespace, collection: dict[str, Any]) -> None:
    for flag, key in (
        ("no_command_line", "command_line"),
        ("no_hashes", "hashes"),
        ("no_signatures", "signatures"),
        ("no_resources", "resources"),
        ("no_connections", "connections"),
    ):
        if getattr(args, flag):
            collection[key] = False


def _collection_limits(args: argparse.Namespace, collection: dict[str, Any]) -> None:
    overrides = {
        "max_processes": args.max_processes,
        "workers": args.collection_workers,
    }
    for key, value in overrides.items():
        if value is not None:
            collection[key] = value


def _jev_overrides(args: argparse.Namespace, jev: dict[str, Any]) -> None:
    for name in ("model", "max_requests", "concurrency"):
        value = getattr(args, name)
        if value is not None:
            jev[name] = value
    if args.demo:
        jev["requests_per_minute"] = 0


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
    if report.summary["incomplete"]:
        return 2
    if fail_on != "none" and report.summary["warnings"]:
        return 1
    if fail_on == "any" and report.summary["uncertain_warnings"]:
        return 1
    return 0


async def _cycles(args: argparse.Namespace, config: Config, engine: Engine, stdout: TextIO) -> int:
    code = 0
    while True:
        # Collection is synchronous and bounded by the selected process/file budgets.
        snapshot = _snapshot(args, config)
        if args.save_snapshot is not None:
            write_private(args.save_snapshot, (snapshot.model_dump_json(indent=2) + "\n").encode())
        mode = "demo" if args.demo else "offline" if args.offline else "live"
        if args.format == "json":
            report = await engine.scan(snapshot, mode=mode)
            render(
                report,
                stdout,
                verbose=args.verbose,
                format_name=args.format,
                width=args.width,
                color=args.color,
            )
        else:
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
        code = max(code, exit_code(report, args.fail_on))
        if args.watch is None or report.summary["incomplete"]:
            return code
        await asyncio.sleep(args.watch)


async def _run(args: argparse.Namespace, config: Config, stdout: TextIO, stderr: TextIO) -> int:
    if args.offline:
        return await _cycles(args, config, Engine(config), stdout)
    api_key = "synthetic-demo-key" if args.demo else os.environ.get("TYPESAFE_API_KEY", "")
    origin = "https://api.typesafe.ai" if args.demo else os.environ.get("TYPESAFE_BASE_URL", "https://api.typesafe.ai")
    async with JevClient(
        config.jev, api_key, base_url=origin, transport=demo_transport() if args.demo else None
    ) as client:
        if not args.demo:
            Terminal(stderr, color=args.color, width=args.width).line(
                "Live mode sends sanitized process metadata to the configured TypeSafe endpoint. "
                "Target environments and memory are not read; binary contents are never submitted. Use --offline for local inventory.",
                style="\x1b[2m",
            )
        with ExitStack() as stack:
            cache = None
            if config.cache.enabled:
                cache = stack.enter_context(AnswerCache(args.cache_dir or default_cache_dir(), config.cache))
            return await _cycles(args, config, Engine(config, client, cache), stdout)


def _validate_args(p: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    invalid = (
        (
            bool(args.watch and any((args.demo, args.input, args.save_snapshot, args.format == "json"))),
            "--watch requires live collection, text/jsonl output, and no --save-snapshot",
        ),
        (
            bool(args.demo and any((args.input, args.pid, args.family, args.save_snapshot))),
            "--demo cannot be combined with --input, --pid, --family or --save-snapshot",
        ),
        (
            bool(args.input and any((args.pid, args.family))),
            "--pid/--family cannot be combined with --input",
        ),
    )
    message = next((message for failed, message in invalid if failed), None)
    if message is not None:
        p.error(message)


def _safe_error(message: str) -> int:
    Terminal(sys.stderr, color="never").line(message)
    return 2


def _execute(args: argparse.Namespace) -> int:
    config = _settings(args)
    return asyncio.run(_run(args, config, sys.stdout, sys.stderr))


def _guarded_execute(args: argparse.Namespace) -> int:
    try:
        return _execute(args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    except (ConfigError, CollectionError, StorageError, JevError) as exc:
        return _safe_error(f"jevproc: {exc}")
    except (OSError, sqlite3.Error, ValidationError, UnicodeError) as exc:
        return _safe_error(f"jevproc: operation failed ({type(exc).__name__}); no clean result is implied")
    except ExceptionGroup as exc:
        return _safe_error(f"jevproc: worker failed ({type(exc).__name__}); scan incomplete")


def main(argv: list[str] | None = None) -> int:
    p = parser()
    args = p.parse_args(argv)
    if args.print_default_config:
        sys.stdout.write(default_yaml())
        return 0
    _validate_args(p, args)
    return _guarded_execute(args)
