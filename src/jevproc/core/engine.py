"""Fixed worker pool, bounded shared-state batches and visible failure/coverage accounting."""

import asyncio
import time
from collections import Counter
from typing import Literal

from jevproc.core.assessment import assess
from jevproc.core.client import JevClient
from jevproc.core.config import Config
from jevproc.core.models import Assessment, Process, Report, RuleResult, Snapshot
from jevproc.core.protocol import Batch, ContextLimitError, JevError, make_batch, plan_batches
from jevproc.core.storage import AnswerCache, request_key


def _unavailable(process: Process, reason: str, *, failure: bool = False) -> Assessment:
    return Assessment(process=process, status="not_evaluated", error=reason if failure else None,
                      rules=[RuleResult(rule="coverage", title="Collection / evaluation", status="unknown", message=reason)])


class Engine:
    def __init__(self, config: Config, client: JevClient | None = None, cache: AnswerCache | None = None):
        self.config, self.client, self.cache = config, client, cache

    async def _batch(self, snapshot: Snapshot, batch: Batch) -> list[Assessment]:
        assert self.client is not None
        if not batch.checks:
            return [_unavailable(p, "No configured rules have the required evidence.") for p in batch.processes]
        key = request_key(self.client.base_url, batch.body)
        try:
            answer = self.cache.get(key, batch.questions) if self.cache else None
            if answer and self.config.jev.model not in {"jev-latest", "jev-preview"} and answer.model != self.config.jev.model:
                assert self.cache is not None
                self.cache.delete(key)
                answer = None
            cached = answer is not None
            if answer is None:
                answer = await self.client.evaluate(batch.body, batch.questions)
                if self.cache:
                    self.cache.put(key, answer)
        except ContextLimitError:
            if len(batch.processes) == 1:
                return [_unavailable(batch.processes[0], "Context rejected; process was not evaluated or silently truncated.", failure=True)]
            midpoint = len(batch.processes) // 2
            first = await self._batch(snapshot, make_batch(snapshot, batch.processes[:midpoint], self.config))
            second = await self._batch(snapshot, make_batch(snapshot, batch.processes[midpoint:], self.config))
            return first + second
        except JevError as exc:
            return [_unavailable(p, str(exc), failure=True) for p in batch.processes]
        return [assess(p, self.config.active_rules, answer.answers, answer.model, cached) for p in batch.processes]

    async def scan(self, snapshot: Snapshot, mode: Literal["live", "offline", "demo"] = "live") -> Report:
        started = time.monotonic()
        before = self._counters()
        assessments: list[Assessment] = []
        candidates: list[Process] = []
        for process in snapshot.processes:
            if mode == "offline":
                assessments.append(_unavailable(process, "Offline inventory only; Jev did not classify this process."))
            elif process.freshness != "observed" or process.created_at is None:
                assessments.append(_unavailable(process, f"Process identity is {process.freshness}; not submitted to Jev."))
            else:
                candidates.append(process)
        if candidates:
            assert self.client is not None
            batches, oversized = plan_batches(snapshot, candidates, self.config)
            assessments.extend(_unavailable(p, "Process evidence exceeds the request budget; not silently truncated.", failure=True) for p in oversized)
            queue: asyncio.Queue[Batch] = asyncio.Queue()
            for batch in batches:
                queue.put_nowait(batch)

            async def worker() -> None:
                while True:
                    try:
                        item = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        return
                    assessments.extend(await self._batch(snapshot, item))

            # At most concurrency tasks, not one unbounded task per process.
            async with asyncio.TaskGroup() as group:
                for _ in range(min(self.config.jev.concurrency, len(batches))):
                    group.create_task(worker())
        assessments.sort(key=lambda a: a.process.pid)
        counts = Counter(a.status for a in assessments)
        operational_failures = sum(a.error is not None for a in assessments)
        after = self._counters()
        summary = {
            "processes": len(snapshot.processes), "omitted": snapshot.omitted,
            "evaluated": sum(a.model is not None for a in assessments),
            "warnings": counts["warning"], "uncertain_warnings": counts["uncertain_warning"],
            "unknown": counts["unknown"], "not_evaluated": counts["not_evaluated"],
            "probably_legitimate": counts["probably_legitimate"], "no_warning": counts["no_warning"],
            "coverage_limited": sum(any(v in {"denied", "unavailable", "partial", "truncated", "gone"} for v in p.coverage.values()) for p in snapshot.processes),
            "unstable_processes": sum(p.freshness != "observed" for p in snapshot.processes),
            "failed_processes": operational_failures,
            "incomplete": bool(operational_failures or snapshot.omitted),
            "cached_processes": sum(a.cached for a in assessments),
            "requests": after[0] - before[0], "request_attempts_total": after[0],
            "retries": after[1] - before[1], "input_tokens": after[2] - before[2],
            "output_tokens": after[3] - before[3], "elapsed_seconds": round(time.monotonic() - started, 3),
            "synthetic": snapshot.synthetic or mode == "demo",
        }
        return Report(mode=mode, snapshot_time=snapshot.captured_at, model_requested=self.config.jev.model,
                      assessments=assessments, summary=summary)

    def _counters(self) -> tuple[int, int, int, int]:
        if self.client is None:
            return (0, 0, 0, 0)
        return (self.client.requests, self.client.retries, self.client.input_tokens, self.client.output_tokens)
