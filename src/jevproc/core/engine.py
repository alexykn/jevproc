"""Concurrent one-process-per-request Jev evaluation with visible failure accounting."""

import asyncio
import time
from collections import Counter
from collections.abc import Callable, Mapping
from typing import Literal, Protocol

from jevproc.core.assessment import assess
from jevproc.core.config import Config, Question
from jevproc.core.models import Assessment, Process, Report, RuleResult, Snapshot
from jevproc.core.protocol import (
    ContextLimitError,
    EvaluationRequest,
    JevError,
    JevResponse,
    make_request,
)
from jevproc.core.storage import AnswerCache, request_key


class EvaluationClient(Protocol):
    base_url: str
    requests: int
    retries: int
    input_tokens: int
    output_tokens: int

    async def evaluate(self, body: bytes, questions: Mapping[str, Question]) -> JevResponse: ...


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
        client: EvaluationClient | None = None,
        cache: AnswerCache | None = None,
    ):
        self.config, self.client, self.cache = config, client, cache

    def _cached_answer(self, key: str, questions: Mapping[str, Question]) -> JevResponse | None:
        if self.cache is None:
            return None
        answer = self.cache.get(key, questions)
        if (
            answer
            and self.config.jev.model not in {"jev-latest", "jev-preview"}
            and answer.model != self.config.jev.model
        ):
            self.cache.delete(key)
            return None
        return answer

    async def _answer(self, request: EvaluationRequest) -> tuple[JevResponse, bool]:
        assert self.client is not None
        key = request_key(self.client.base_url, request.body)
        cached = self._cached_answer(key, request.questions)
        if cached is not None:
            return cached, True
        answer = await self.client.evaluate(request.body, request.questions)
        if self.cache is not None:
            self.cache.put(key, answer)
        return answer, False

    async def _evaluate(self, snapshot: Snapshot, process: Process) -> Assessment:
        request = make_request(snapshot, process, self.config)
        if not request.checks:
            return _unavailable(process, "No configured rules have the required evidence.")
        try:
            answer, cached = await self._answer(request)
        except ContextLimitError:
            return _unavailable(
                process,
                "This process request exceeded Jev's context limit; no evidence was silently truncated.",
                failure=True,
            )
        except JevError as exc:
            return _unavailable(process, str(exc), failure=True)
        return assess(process, self.config.active_rules, answer.answers, answer.model, cached)

    async def scan(
        self,
        snapshot: Snapshot,
        mode: Literal["live", "offline", "demo"] = "live",
        on_assessment: Callable[[Assessment], None] | None = None,
    ) -> Report:
        started = time.monotonic()
        before = self._counters()
        assessments: list[Assessment] = []
        candidates: list[Process] = []
        for process in snapshot.processes:
            initial = _initial_assessment(process, mode)
            if initial is None:
                candidates.append(process)
                continue
            assessments.append(initial)
            if on_assessment is not None:
                on_assessment(initial)
        await self._evaluate_pending(snapshot, candidates, assessments, on_assessment)
        assessments.sort(key=lambda assessment: assessment.process.pid)
        return Report(
            mode=mode,
            snapshot_time=snapshot.captured_at,
            model_requested=self.config.jev.model,
            assessments=assessments,
            summary=_scan_summary(snapshot, assessments, before, self._counters(), started, mode),
        )

    async def _worker(
        self,
        snapshot: Snapshot,
        queue: asyncio.Queue[Process],
        assessments: list[Assessment],
        on_assessment: Callable[[Assessment], None] | None,
    ) -> None:
        while True:
            try:
                process = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            result = await self._evaluate(snapshot, process)
            assessments.append(result)
            if on_assessment is not None:
                on_assessment(result)

    async def _evaluate_pending(
        self,
        snapshot: Snapshot,
        candidates: list[Process],
        assessments: list[Assessment],
        on_assessment: Callable[[Assessment], None] | None,
    ) -> None:
        queue: asyncio.Queue[Process] = asyncio.Queue()
        for process in candidates:
            queue.put_nowait(process)
        async with asyncio.TaskGroup() as group:
            for _ in range(min(self.config.jev.concurrency, len(candidates))):
                group.create_task(self._worker(snapshot, queue, assessments, on_assessment))

    def _counters(self) -> tuple[int, int, int, int]:
        if self.client is None:
            return (0, 0, 0, 0)
        return (
            self.client.requests,
            self.client.retries,
            self.client.input_tokens,
            self.client.output_tokens,
        )


_LIMITED_COVERAGE = frozenset({"denied", "unavailable", "partial", "truncated", "gone"})


def _coverage_limited(process: Process) -> bool:
    return bool(_LIMITED_COVERAGE.intersection(process.coverage.values()))


def _status_summary(assessments: list[Assessment]) -> dict[str, int]:
    counts = Counter(assessment.status for assessment in assessments)
    return {
        "warnings": counts["warning"],
        "uncertain_warnings": counts["uncertain_warning"],
        "unknown": counts["unknown"],
        "not_evaluated": counts["not_evaluated"],
        "probably_legitimate": counts["probably_legitimate"],
        "no_warning": counts["no_warning"],
    }


def _request_summary(
    before: tuple[int, int, int, int],
    after: tuple[int, int, int, int],
) -> dict[str, int]:
    return {
        "requests": after[0] - before[0],
        "request_attempts_total": after[0],
        "retries": after[1] - before[1],
        "input_tokens": after[2] - before[2],
        "output_tokens": after[3] - before[3],
    }


def _scan_summary(
    snapshot: Snapshot,
    assessments: list[Assessment],
    before: tuple[int, int, int, int],
    after: tuple[int, int, int, int],
    started: float,
    mode: str,
) -> dict:
    operational_failures = sum(assessment.error is not None for assessment in assessments)
    return {
        "processes": len(snapshot.processes),
        "omitted": snapshot.omitted,
        "evaluated": sum(assessment.model is not None for assessment in assessments),
        **_status_summary(assessments),
        "coverage_limited": sum(map(_coverage_limited, snapshot.processes)),
        "unstable_processes": sum(process.freshness != "observed" for process in snapshot.processes),
        "failed_processes": operational_failures,
        "incomplete": bool(operational_failures or snapshot.omitted),
        "cached_processes": sum(assessment.cached for assessment in assessments),
        **_request_summary(before, after),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "synthetic": snapshot.synthetic or mode == "demo",
    }


def _initial_assessment(process: Process, mode: str) -> Assessment | None:
    if mode == "offline":
        return _unavailable(process, "Offline inventory only; Jev did not classify this process.")
    if process.freshness != "observed" or process.created_at is None:
        return _unavailable(process, f"Process identity is {process.freshness}; not submitted to Jev.")
    return None
