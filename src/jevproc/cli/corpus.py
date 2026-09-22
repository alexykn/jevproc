"""Run the packaged synthetic corpus against live Jev."""

import argparse
import asyncio
import json
import os
import sys
from typing import Any

from pydantic import ValidationError

from jevproc import __version__
from jevproc.cli.render import Terminal
from jevproc.core.client import JevClient
from jevproc.core.config import Config, ConfigError, load_config
from jevproc.core.corpus import CorpusCase, load_corpus, matches, selected_cases, snapshot_for
from jevproc.core.engine import Engine
from jevproc.core.models import Assessment
from jevproc.core.protocol import JevError


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jevproc-test",
        description="Run jevproc's packaged synthetic process corpus against live Jev.",
    )
    p.add_argument("--version", action="version", version=f"jevproc-test {__version__}")
    p.add_argument("--list", action="store_true", help="list corpus cases without contacting Jev")
    p.add_argument("--case", action="append", default=[], metavar="ID", help="run one corpus case (repeatable)")
    p.add_argument("--config", help="explicit jevproc YAML policy/config override")
    p.add_argument("--model", help="Jev model ID override")
    p.add_argument("--concurrency", type=int, help="maximum concurrent corpus requests")
    p.add_argument("--format", choices=["text", "json", "jsonl"], default="text")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    return p


def _settings(args: argparse.Namespace) -> Config:
    from pathlib import Path

    config = load_config(Path(args.config) if args.config else None)
    data = config.model_dump(mode="json")
    data["cache"]["enabled"] = False
    if args.model:
        data["jev"]["model"] = args.model
    if args.concurrency is not None:
        if args.concurrency < 1:
            raise ConfigError("concurrency must be at least 1")
        data["jev"]["concurrency"] = args.concurrency
    return Config.model_validate(data)


def _answer_summary(assessment: Assessment) -> str:
    parts = []
    for rule in assessment.rules:
        answer = rule.answer
        if answer.get("type") == "noul":
            value = f"{rule.rule}=noul:{answer['noul']:.3f}"
        elif answer.get("type") == "choice":
            value = f"{rule.rule}={answer['choice']}"
        elif answer.get("type") == "score":
            value = f"{rule.rule}=score:{answer['score']:.3f}"
        else:
            value = f"{rule.rule}={rule.status}"
        parts.append(value)
    return " ".join(parts)


def _case_payload(case: CorpusCase, assessment: Assessment) -> dict[str, Any]:
    return {
        "id": case.id,
        "description": case.description,
        "expected_statuses": case.expected_statuses,
        "actual_status": assessment.status,
        "passed": matches(case, assessment.status),
        "cached": assessment.cached,
        "model": assessment.model,
        "error": assessment.error,
        "rules": [rule.model_dump(mode="json") for rule in assessment.rules],
    }


async def _run(args: argparse.Namespace) -> int:
    corpus = load_corpus()
    cases = selected_cases(corpus, args.case)

    if args.list:
        if args.format == "json":
            sys.stdout.write(
                json.dumps(
                    [
                        {
                            "id": case.id,
                            "expected_statuses": case.expected_statuses,
                            "description": case.description,
                        }
                        for case in cases
                    ],
                    indent=2,
                )
                + "\n"
            )
        else:
            for case in cases:
                expected = "|".join(case.expected_statuses)
                sys.stdout.write(f"{case.id}\texpected={expected}\t{case.description}\n")
        return 0

    config = _settings(args)
    snapshot = snapshot_for(corpus, cases)
    by_pid = {case.process.pid: case for case in cases}
    results: list[dict[str, Any]] = []
    term = Terminal(sys.stdout, color=args.color)

    if args.format == "text":
        term.line(
            f"jevproc-test  live  model={config.jev.model}  cases={len(cases)}",
            style="\x1b[1;36m",
        )
        term.line(
            "Synthetic metadata only; no corpus executable, payload, or network target is run.",
            style="\x1b[2m",
        )
        sys.stdout.flush()
    elif args.format == "jsonl":
        sys.stdout.write(
            json.dumps(
                {
                    "event": "start",
                    "schema_version": 1,
                    "model": config.jev.model,
                    "cases": len(cases),
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        sys.stdout.flush()

    def emit(assessment: Assessment) -> None:
        case = by_pid[assessment.process.pid]
        payload = _case_payload(case, assessment)
        results.append(payload)
        if args.format == "json":
            return
        if args.format == "jsonl":
            sys.stdout.write(
                json.dumps({"event": "case", **payload}, separators=(",", ":")) + "\n"
            )
            sys.stdout.flush()
            return
        passed = payload["passed"]
        marker = "PASS" if passed else "FAIL"
        style = "\x1b[32m" if passed else "\x1b[31m"
        expected = "|".join(case.expected_statuses)
        detail = _answer_summary(assessment)
        term.line(
            f"{marker:<4}  {case.id}  expected={expected}  got={assessment.status}"
            + (f"  {detail}" if detail else ""),
            style=style,
        )
        if assessment.error:
            term.line(f"error: {assessment.error}", indent=6, style="\x1b[31m")
        sys.stdout.flush()

    api_key = os.environ.get("TYPESAFE_API_KEY", "")
    origin = os.environ.get("TYPESAFE_BASE_URL", "https://api.typesafe.ai")
    async with JevClient(config.jev, api_key, base_url=origin) as client:
        report = await Engine(config, client).scan(snapshot, mode="live", on_assessment=emit)

    # Completion-order streaming is useful interactively; stable order is useful for JSON.
    stable = sorted(results, key=lambda item: item["id"])
    mismatches = sum(not item["passed"] for item in stable)
    failures = report.summary["failed_processes"]
    summary = {
        "cases": len(stable),
        "passed": len(stable) - mismatches,
        "mismatches": mismatches,
        "operational_failures": failures,
        "requests": report.summary["requests"],
        "retries": report.summary["retries"],
        "input_tokens": report.summary["input_tokens"],
        "elapsed_seconds": report.summary["elapsed_seconds"],
    }

    if args.format == "json":
        sys.stdout.write(
            json.dumps(
                {
                    "schema_version": 1,
                    "model": config.jev.model,
                    "results": stable,
                    "summary": summary,
                },
                indent=2,
            )
            + "\n"
        )
    elif args.format == "jsonl":
        sys.stdout.write(json.dumps({"event": "summary", **summary}, separators=(",", ":")) + "\n")
    else:
        term.line()
        style = "\x1b[32m" if not mismatches and not failures else "\x1b[31m"
        term.line(
            f"corpus: {summary['passed']}/{summary['cases']} passed  "
            f"mismatches={mismatches}  failures={failures}  "
            f"requests={summary['requests']}  input-tokens={summary['input_tokens']}  "
            f"elapsed={summary['elapsed_seconds']:.2f}s",
            style="\x1b[1m" + style,
        )
        sys.stdout.flush()

    if failures:
        return 2
    return 1 if mismatches else 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    except (ConfigError, JevError, ValueError) as exc:
        Terminal(sys.stderr, color="never").line(f"jevproc-test: {exc}")
        return 2
    except ValidationError:
        Terminal(sys.stderr, color="never").line(
            "jevproc-test: corpus/config validation failed; no classification result is implied"
        )
        return 2
