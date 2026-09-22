"""Run the packaged synthetic corpus and calibrate raw Jev Noul operating points."""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from jevproc import __version__
from jevproc.cli.render import Terminal
from jevproc.core.calibration import calibration_report
from jevproc.core.client import JevClient
from jevproc.core.config import Config, ConfigError, NoulQuestion, load_config
from jevproc.core.corpus import CorpusCase, load_corpus, matches, selected_cases, snapshot_for
from jevproc.core.engine import Engine
from jevproc.core.models import Assessment
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


def _selected(args: argparse.Namespace) -> list[CorpusCase]:
    corpus = load_corpus()
    cases = selected_cases(corpus, args.case)
    if args.label:
        labels = set(args.label)
        cases = [case for case in cases if case.label in labels]
    if not cases:
        raise ValueError("corpus selection is empty")
    return cases


def _noul(assessment: Assessment) -> float | None:
    for rule in assessment.rules:
        if rule.rule == "JPR001" and rule.answer.get("type") == "noul":
            return float(rule.answer["noul"])
    return None


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


def _case_payload(case: CorpusCase, assessment: Assessment, run: int) -> dict[str, Any]:
    return {
        "run": run,
        "id": case.id,
        "label": case.label,
        "tier": case.tier,
        "tags": case.tags,
        "description": case.description,
        "expected_statuses": case.expected_statuses,
        "actual_status": assessment.status,
        "noul": _noul(assessment),
        "passed": matches(case, assessment.status),
        "cached": assessment.cached,
        "model": assessment.model,
        "error": assessment.error,
        "rules": [rule.model_dump(mode="json") for rule in assessment.rules],
    }


def _policy(config: Config) -> tuple[float, float]:
    rule = next((rule for rule in config.active_rules if rule.id == "JPR001"), None)
    if rule is None or not isinstance(rule.question, NoulQuestion):
        raise ConfigError("--calibrate requires active Noul rule JPR001")
    return rule.policy.uncertain_at, rule.policy.warning_at


def _fmt_stats(stats: dict[str, Any]) -> str:
    if not stats.get("n"):
        return "n=0"
    return (
        f"n={stats['n']} mean={stats['mean']:.3f} stdev={stats['stdev']:.3f} "
        f"min={stats['min']:.3f} p10={stats['p10']:.3f} p50={stats['median']:.3f} "
        f"p90={stats['p90']:.3f} p95={stats['p95']:.3f} max={stats['max']:.3f}"
    )


def _fmt_pair(name: str, pair: dict[str, float]) -> str:
    return (
        f"{name:<22} uncertain={pair['uncertain_at']:.3f} warning={pair['warning_at']:.3f}  "
        f"macro={pair['macro_recall']:.1%} exact={pair['exact_accuracy']:.1%}  "
        f"benign-fp={pair['benign_false_positive_rate']:.1%} "
        f"benign-warning={pair['benign_warning_rate']:.1%}  "
        f"ambiguous-band={pair['ambiguous_band_recall']:.1%} "
        f"suspicious-warning={pair['suspicious_warning_recall']:.1%}"
    )


async def _run(args: argparse.Namespace) -> int:
    corpus = load_corpus()
    cases = _selected(args)
    runs = args.runs or (3 if args.calibrate else 1)

    if args.list:
        rows = [
            {
                "id": case.id,
                "label": case.label,
                "tier": case.tier,
                "tags": case.tags,
                "expected_statuses": case.expected_statuses,
                "description": case.description,
            }
            for case in cases
        ]
        if args.format == "json":
            sys.stdout.write(json.dumps(rows, indent=2) + "\n")
        else:
            for row in rows:
                expected = "|".join(row["expected_statuses"])
                tags = ",".join(row["tags"])
                sys.stdout.write(
                    f"{row['id']}\tlabel={row['label']}\ttier={row['tier']}\t"
                    f"expected={expected}\ttags={tags}\t{row['description']}\n"
                )
        return 0

    config = _settings(args)
    current_uncertain, current_warning = _policy(config)
    snapshot = snapshot_for(corpus, cases)
    by_pid = {case.process.pid: case for case in cases}
    results: list[dict[str, Any]] = []
    samples: dict[str, list[float]] = {case.id: [] for case in cases}
    term = Terminal(sys.stdout, color=args.color)
    reports = []

    if args.format == "text":
        mode = "calibration" if args.calibrate else "regression"
        term.line(
            f"jevproc-test  {mode}  model={config.jev.model}  cases={len(cases)}  runs={runs}",
            style="\x1b[1;36m",
        )
        term.line(
            "Synthetic metadata only; no corpus executable, payload, or network target is run.",
            style="\x1b[2m",
        )
        if args.calibrate:
            term.line(
                "Calibration uses raw JPR001 Noul scores; candidate thresholds are never applied automatically.",
                style="\x1b[2m",
            )
        sys.stdout.flush()
    elif args.format == "jsonl":
        sys.stdout.write(
            json.dumps(
                {
                    "event": "start",
                    "schema_version": 2,
                    "model": config.jev.model,
                    "cases": len(cases),
                    "runs": runs,
                    "calibrate": args.calibrate,
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        sys.stdout.flush()

    api_key = os.environ.get("TYPESAFE_API_KEY", "")
    origin = os.environ.get("TYPESAFE_BASE_URL", "https://api.typesafe.ai")

    async with JevClient(config.jev, api_key, base_url=origin) as client:
        engine = Engine(config, client)
        for run in range(1, runs + 1):
            run_results: list[dict[str, Any]] = []

            def emit(assessment: Assessment, run_number: int = run) -> None:
                case = by_pid[assessment.process.pid]
                payload = _case_payload(case, assessment, run_number)
                results.append(payload)
                run_results.append(payload)
                if payload["noul"] is not None:
                    samples[case.id].append(payload["noul"])

                if args.format == "json":
                    return
                if args.format == "jsonl":
                    sys.stdout.write(
                        json.dumps({"event": "sample", **payload}, separators=(",", ":")) + "\n"
                    )
                    sys.stdout.flush()
                    return
                if args.calibrate:
                    return
                passed = payload["passed"]
                marker = "PASS" if passed else "FAIL"
                style = "\x1b[32m" if passed else "\x1b[31m"
                expected = "|".join(case.expected_statuses)
                detail = _answer_summary(assessment)
                term.line(
                    f"{marker:<4} run={run_number}  {case.id}  label={case.label}  "
                    f"expected={expected}  got={assessment.status}"
                    + (f"  {detail}" if detail else ""),
                    style=style,
                )
                if assessment.error:
                    term.line(f"error: {assessment.error}", indent=6, style="\x1b[31m")
                sys.stdout.flush()

            report = await engine.scan(snapshot, mode="live", on_assessment=emit)
            reports.append(report)
            if args.format == "text" and args.calibrate:
                failures = report.summary["failed_processes"]
                scored = sum(item["noul"] is not None for item in run_results)
                term.line(
                    f"run {run}/{runs}: scored={scored}/{len(cases)}  failures={failures}  "
                    f"requests={report.summary['requests']}  input={report.summary['input_tokens']}  "
                    f"elapsed={report.summary['elapsed_seconds']:.2f}s",
                    style="\x1b[2m" if not failures else "\x1b[31m",
                )
                sys.stdout.flush()

    stable = sorted(results, key=lambda item: (item["id"], item["run"]))
    mismatches = sum(not item["passed"] for item in stable)
    failures = sum(report.summary["failed_processes"] for report in reports)
    summary = {
        "cases": len(cases),
        "runs": runs,
        "samples": len(stable),
        "passed_samples": len(stable) - mismatches,
        "mismatches": mismatches,
        "operational_failures": failures,
        "requests": sum(report.summary["requests"] for report in reports),
        "retries": sum(report.summary["retries"] for report in reports),
        "input_tokens": sum(report.summary["input_tokens"] for report in reports),
        "elapsed_seconds": sum(report.summary["elapsed_seconds"] for report in reports),
    }

    calibration = None
    if args.calibrate and not failures:
        missing = [case.id for case in cases if not samples[case.id]]
        if missing:
            raise JevError("calibration missing JPR001 Noul samples for: " + ", ".join(missing))
        calibration = calibration_report(
            cases,
            samples,
            current_uncertain=current_uncertain,
            current_warning=current_warning,
        )

    if args.format == "json":
        document: dict[str, Any] = {
            "schema_version": 2,
            "model": config.jev.model,
            "results": stable,
            "summary": summary,
        }
        if calibration is not None:
            document["calibration"] = calibration
        sys.stdout.write(json.dumps(document, indent=2) + "\n")
    elif args.format == "jsonl":
        if calibration is not None:
            sys.stdout.write(
                json.dumps({"event": "calibration", **calibration}, separators=(",", ":")) + "\n"
            )
        sys.stdout.write(json.dumps({"event": "summary", **summary}, separators=(",", ":")) + "\n")
    elif calibration is not None:
        term.line()
        term.line("Raw JPR001 Noul distributions", style="\x1b[1m")
        for label in ("benign", "ambiguous", "suspicious", "unknown"):
            term.line(f"{label:<11} {_fmt_stats(calibration['distributions'][label])}", indent=2)

        separation = calibration["separation"]
        term.line()
        term.line("Case-mean separation", style="\x1b[1m")
        term.line(
            f"max benign={separation['max_benign_mean']:.3f}  "
            f"min ambiguous={separation['min_ambiguous_mean']:.3f}  "
            f"min suspicious={separation['min_suspicious_mean']:.3f}",
            indent=2,
        )
        term.line(
            f"benign→ambiguous gap={separation['benign_to_ambiguous_gap']:+.3f}  "
            f"benign→suspicious gap={separation['benign_to_suspicious_gap']:+.3f}",
            indent=2,
        )

        term.line()
        term.line("Candidate threshold pairs (descriptive only; NOT applied)", style="\x1b[1m")
        for name in ("current", "balanced", "zero_benign_fp", "high_suspicious_recall"):
            term.line(_fmt_pair(name, calibration["candidates"][name]), indent=2)

        term.line()
        term.line("Most variable cases across runs", style="\x1b[1m")
        for item in calibration["most_unstable"][:8]:
            term.line(
                f"{item['id']:<38} label={item['label']:<10} mean={item['mean']:.3f} "
                f"stdev={item['stdev']:.3f} range={item['min']:.3f}–{item['max']:.3f}",
                indent=2,
            )
        term.line(calibration["note"], style="\x1b[2m")
        term.line()
        term.line(
            f"calibration: cases={summary['cases']} runs={runs} samples={summary['samples']} "
            f"failures={failures} requests={summary['requests']} input-tokens={summary['input_tokens']} "
            f"elapsed={summary['elapsed_seconds']:.2f}s",
            style="\x1b[1m",
        )
    else:
        term.line()
        style = "\x1b[32m" if not mismatches and not failures else "\x1b[31m"
        term.line(
            f"corpus: {summary['passed_samples']}/{summary['samples']} samples passed  "
            f"mismatches={mismatches}  failures={failures}  "
            f"requests={summary['requests']}  input-tokens={summary['input_tokens']}  "
            f"elapsed={summary['elapsed_seconds']:.2f}s",
            style="\x1b[1m" + style,
        )
        sys.stdout.flush()

    if failures:
        return 2
    # Calibration is observational: current policy mismatches are the thing being measured.
    if args.calibrate:
        return 0
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


if __name__ == "__main__":
    raise SystemExit(main())
