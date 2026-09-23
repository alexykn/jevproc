"""Arguments and application composition for synthetic corpus checks."""

import argparse
import asyncio
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from jevproc import __version__
from jevproc.cli.corpus_render import CorpusReporter, render_case_list
from jevproc.cli.render import Terminal
from jevproc.core.client import JevClient
from jevproc.core.config import Config, ConfigError, NoulQuestion, load_config
from jevproc.core.corpus import (
    Corpus,
    CorpusCase,
    load_corpus,
    selected_cases,
    snapshot_for,
)
from jevproc.core.engine import Engine
from jevproc.core.experiments import require_calibration_labels, run_corpus
from jevproc.core.protocol import JevError


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jevproc-test",
        description="Run jevproc's packaged synthetic process corpus against live Jev.",
    )
    p.add_argument("--version", action="version", version=f"jevproc-test {__version__}")
    p.add_argument("--list", action="store_true", help="list corpus cases without contacting Jev")
    p.add_argument("--case", action="append", default=[], metavar="ID", help="run one corpus case (repeatable)")
    p.add_argument(
        "--label",
        action="append",
        choices=["benign", "suspicious", "ambiguous", "unknown"],
        default=[],
        help="select corpus labels (repeatable)",
    )
    p.add_argument(
        "--calibrate",
        action="store_true",
        help="analyze raw JPR001 Noul distributions and candidate threshold pairs",
    )
    p.add_argument(
        "--runs",
        type=positive_int,
        help="repeat every selected case N times; defaults to 3 with --calibrate, otherwise 1",
    )
    p.add_argument("--config", type=Path, help="explicit jevproc YAML policy/config override")
    p.add_argument("--model", help="Jev model ID override")
    p.add_argument("--concurrency", type=positive_int, help="maximum concurrent corpus requests")
    p.add_argument("--format", choices=["text", "json", "jsonl"], default="text")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    return p


def _settings(args: argparse.Namespace) -> Config:
    config = load_config(args.config)
    data = config.model_dump(mode="json")
    data["cache"]["enabled"] = False
    if args.model:
        data["jev"]["model"] = args.model
    if args.concurrency is not None:
        data["jev"]["concurrency"] = args.concurrency
    return Config.model_validate(data)


def _selected(args: argparse.Namespace, corpus: Corpus) -> list[CorpusCase]:
    cases = selected_cases(corpus, args.case)
    if args.label:
        labels = set(args.label)
        cases = [case for case in cases if case.label in labels]
    if not cases:
        raise ValueError("corpus selection is empty")
    return cases


def _policy(config: Config) -> tuple[float, float]:
    rule = next((rule for rule in config.active_rules if rule.id == "JPR001"), None)
    if rule is None or not isinstance(rule.question, NoulQuestion):
        raise ConfigError("--calibrate requires active Noul rule JPR001")
    return rule.policy.uncertain_at, rule.policy.warning_at


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


def _run_count(args: argparse.Namespace) -> int:
    return args.runs or (3 if args.calibrate else 1)


def _corpus_reporter(args: argparse.Namespace, config: Config, cases: list[CorpusCase], runs: int) -> CorpusReporter:
    return CorpusReporter(
        sys.stdout,
        model=config.jev.model,
        cases=len(cases),
        runs=runs,
        calibrating=args.calibrate,
        format_name=args.format,
        color=args.color,
    )


async def _experiment(
    config: Config,
    corpus: Corpus,
    cases: list[CorpusCase],
    runs: int,
    reporter: CorpusReporter,
):
    api_key = os.environ.get("TYPESAFE_API_KEY", "")
    origin = os.environ.get("TYPESAFE_BASE_URL", "https://api.typesafe.ai")
    async with JevClient(config.jev, api_key, base_url=origin) as client:
        return await run_corpus(
            Engine(config, client),
            snapshot_for(corpus, cases),
            cases,
            runs,
            on_sample=reporter.sample,
            on_run=reporter.run_finished,
        )


async def _run(args: argparse.Namespace) -> int:
    corpus = load_corpus()
    cases = _selected(args, corpus)
    if args.list:
        render_case_list(cases, sys.stdout, args.format)
        return 0

    config = _settings(args)
    uncertain, warning = _policy(config)
    if args.calibrate:
        require_calibration_labels(cases)
    runs = _run_count(args)
    reporter = _corpus_reporter(args, config, cases, runs)
    reporter.start()
    experiment = await _experiment(config, corpus, cases, runs, reporter)
    calibration = experiment.calibrate(uncertain, warning) if args.calibrate else None
    reporter.finish(experiment, calibration)
    return experiment.exit_code(args.calibrate)


if __name__ == "__main__":
    raise SystemExit(main())
