"""Concurrent one-process-per-request Jev evaluation with visible failure accounting."""

import asyncio
import time
from collections import Counter
from typing import Literal

from jevproc.core.assessment import assess
from jevproc.core.client import JevClient
from jevproc.core.config import Config
from jevproc.core.models import Assessment, Process, Report, RuleResult, Snapshot
from jevproc.core.protocol import ContextLimitError, JevError, make_request
from jevproc.core.storage import AnswerCache, request_key


def _unavailable(process: Process, reason: str, *, failure: bool = False) -> Assessment:
    return Assessment(
        process=process,
        status="not_evaluated",
        error=reason if failure else None,
        rules=[
            RuleResult(
                rule="coverage",
                title="Collection / evaluation",
                status="unknown",
                message=reason,
            )
        ],
    )


class Engine:
    def __init__(
        self,
        config: Config,
        client: JevClient | None = None,
        cache: AnswerCache | None = None,
    ):
        self.config, self.client, self.cache = config, client, cache

    async def _evaluate(self, snapshot: Snapshot, process: Process) -> Assessment:
        assert self.client is not None
        request = make_request(snapshot, process, self.config)
        if not request.checks:
            return _unavailable(process, "No configured rules have the required evidence.")

        key = request_key(self.client.base_url, request.body)
        try:
            answer = self.cache.get(key, request.questions) if self.cache else None
            if (
                answer
                and self.config.jev.model not in {"jev-latest", "jev-preview"}
                and answer.model != self.config.jev.model
            ):
                assert self.cache is not None
                self.cache.delete(key)
                answer = None
            cached = answer is not None
            if answer is None:
                answer = await self.client.evaluate(request.body, request.questions)
                if self.cache:
                    self.cache.put(key, answer)
        except ContextLimitError:
            return _unavailable(
                process,
                "This process request exceeded Jev's context limit; no evidence was silently truncated.",
                failure=True,
            )
        except JevError as exc:
            return _unavailable(process, str(exc), failure=True)

        return assess(
            process,
            self.config.active_rules,
            answer.answers,
            answer.model,
            cached,
        )

    async def scan(
        self,
        snapshot: Snapshot,
        mode: Literal["live", "offline", "demo"] = "live",
    ) -> Report:
        started = time.monotonic()
        before = self._counters()
        assessments: list[Assessment] = []
        candidates: list[Process] = []

        for process in snapshot.processes:
            if mode == "offline":
                assessments.append(
                    _unavailable(process, "Offline inventory only; Jev did not classify this process.")
                )
            elif process.freshness != "observed" or process.created_at is None:
                assessments.append(
                    _unavailable(
                        process,
                        f"Process identity is {process.freshness}; not submitted to Jev.",
                    )
                )
            else:
                candidates.append(process)

        if candidates:
            assert self.client is not None
            queue: asyncio.Queue[Process] = asyncio.Queue()
            for process in candidates:
                queue.put_nowait(process)

            async def worker() -> None:
                while True:
                    try:
                        process = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        return
                    assessments.append(await self._evaluate(snapshot, process))

            async with asyncio.TaskGroup() as group:
                for _ in range(min(self.config.jev.concurrency, len(candidates))):
                    group.create_task(worker())

        assessments.sort(key=lambda assessment: assessment.process.pid)
        counts = Counter(assessment.status for assessment in assessments)
        operational_failures = sum(assessment.error is not None for assessment in assessments)
        after = self._counters()
        summary = {
            "processes": len(snapshot.processes),
            "omitted": snapshot.omitted,
            "evaluated": sum(assessment.model is not None for assessment in assessments),
            "warnings": counts["warning"],
            "uncertain_warnings": counts["uncertain_warning"],
            "unknown": counts["unknown"],
            "not_evaluated": counts["not_evaluated"],
            "probably_legitimate": counts["probably_legitimate"],
            "no_warning": counts["no_warning"],
            "coverage_limited": sum(
                any(
                    value in {"denied", "unavailable", "partial", "truncated", "gone"}
                    for value in process.coverage.values()
                )
                for process in snapshot.processes
            ),
            "unstable_processes": sum(
                process.freshness != "observed" for process in snapshot.processes
            ),
            "failed_processes": operational_failures,
            "incomplete": bool(operational_failures or snapshot.omitted),
            "cached_processes": sum(assessment.cached for assessment in assessments),
            "requests": after[0] - before[0],
            "request_attempts_total": after[0],
            "retries": after[1] - before[1],
            "input_tokens": after[2] - before[2],
            "output_tokens": after[3] - before[3],
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "synthetic": snapshot.synthetic or mode == "demo",
        }
        return Report(
            mode=mode,
            snapshot_time=snapshot.captured_at,
            model_requested=self.config.jev.model,
            assessments=assessments,
            summary=summary,
        )

    def _counters(self) -> tuple[int, int, int, int]:
        if self.client is None:
            return (0, 0, 0, 0)
        return (
            self.client.requests,
            self.client.retries,
            self.client.input_tokens,
            self.client.output_tokens,
        )
