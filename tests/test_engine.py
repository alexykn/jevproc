import asyncio
import json

import httpx

from jevproc.core.client import JevClient
from jevproc.core.config import CacheSettings, Config
from jevproc.core.demo import demo_transport
from jevproc.core.engine import Engine
from jevproc.core.protocol import make_request
from jevproc.core.storage import AnswerCache


async def test_synthetic_end_to_end_uses_one_request_per_process(config, snapshot):
    async with JevClient(config.jev, "demo", transport=demo_transport()) as client:
        report = await Engine(config, client).scan(snapshot, "demo")
    assert [result.status for result in report.assessments] == [
        "probably_legitimate",
        "warning",
        "uncertain_warning",
        "unknown",
    ]
    assert report.summary["evaluated"] == 4
    assert report.summary["requests"] == 4
    assert report.summary["warnings"] == 1
    assert report.summary["uncertain_warnings"] == 1


async def test_cache_is_per_process_and_only_changed_process_reexecutes(config, snapshot, tmp_path):
    with AnswerCache(tmp_path / "cache", CacheSettings()) as cache:
        async with JevClient(config.jev, "demo", transport=demo_transport()) as client:
            engine = Engine(config, client, cache)
            first = await engine.scan(snapshot, "demo")
            second = await engine.scan(snapshot, "demo")
            assert first.summary["requests"] == 4
            assert second.summary["requests"] == 0
            assert second.summary["cached_processes"] == 4

            changed_process = snapshot.processes[0].model_copy(update={"executable": "/different/tool"})
            changed = snapshot.model_copy(
                update={"processes": [changed_process, *snapshot.processes[1:]]}
            )
            third = await engine.scan(changed, "demo")
            assert third.summary["requests"] == 1
            assert third.summary["cached_processes"] == 3


async def test_context_rejection_is_process_local(config, snapshot):
    async def handler(request):
        payload = json.loads(request.content)
        pid = payload["state"]["process"]["pid"]
        if pid == 4819:
            return httpx.Response(413)
        answers = {
            key: {"type": "noul", "noul": 0.08}
            for key in payload["questions"]
        }
        return httpx.Response(
            200,
            json={
                "model": payload["model"],
                "answers": answers,
                "usage": {"input_tokens": 10, "output_tokens": 1},
            },
        )

    async with JevClient(
        config.jev, "demo", transport=httpx.MockTransport(handler)
    ) as client:
        report = await Engine(config, client).scan(snapshot, "demo")
    assert report.summary["requests"] == 4
    assert report.summary["evaluated"] == 3
    assert report.summary["failed_processes"] == 1
    failed = next(result for result in report.assessments if result.process.pid == 4819)
    assert failed.status == "not_evaluated"
    assert report.summary["incomplete"]


async def test_transport_failure_preserves_all_processes(config, snapshot):
    async with JevClient(
        config.jev,
        "demo",
        transport=httpx.MockTransport(lambda request: httpx.Response(401)),
    ) as client:
        report = await Engine(config, client).scan(snapshot, "demo")
    assert len(report.assessments) == 4
    assert all(result.status == "not_evaluated" for result in report.assessments)
    assert report.summary["incomplete"]


async def test_offline_never_calls_a_client(config, snapshot):
    class Forbidden:
        requests = retries = input_tokens = output_tokens = 0

        async def evaluate(self, *args):
            raise AssertionError("network access in offline mode")

    report = await Engine(config, Forbidden()).scan(snapshot, "offline")
    assert report.summary["evaluated"] == 0
    assert report.summary["requests"] == 0
    assert report.summary["not_evaluated"] == 4
    assert report.summary["warnings"] == 0


async def test_unstable_identity_not_submitted(config, snapshot):
    process = snapshot.processes[0].model_copy(update={"freshness": "reused"})
    source = snapshot.model_copy(update={"processes": [process]})
    async with JevClient(config.jev, "demo", transport=demo_transport()) as client:
        report = await Engine(config, client).scan(source, "demo")
    assert report.summary["requests"] == 0
    assert report.summary["unstable_processes"] == 1


async def test_hundreds_of_processes_use_independent_bounded_requests(config, snapshot):
    data = config.model_dump(mode="json")
    data["jev"]["concurrency"] = 8
    config = Config.model_validate(data)
    processes = [
        snapshot.processes[0].model_copy(update={"pid": 10000 + index, "ppid": None})
        for index in range(700)
    ]
    source = snapshot.model_copy(update={"processes": processes})
    calls = 0
    active = 0
    peak = 0

    async def handler(request):
        nonlocal calls, active, peak
        calls += 1
        active += 1
        peak = max(peak, active)
        payload = json.loads(request.content)
        assert payload["state"]["process"]["pid"] >= 10000
        assert len(payload["questions"]) == 1
        await asyncio.sleep(0)
        answers = {
            key: {"type": "noul", "noul": 0.08}
            for key in payload["questions"]
        }
        active -= 1
        return httpx.Response(
            200,
            json={
                "model": payload["model"],
                "answers": answers,
                "usage": {"input_tokens": 10, "output_tokens": 1},
            },
        )

    async with JevClient(
        config.jev, "demo", transport=httpx.MockTransport(handler)
    ) as client:
        report = await Engine(config, client).scan(source, "demo")
    assert calls == 700
    assert report.summary["requests"] == 700
    assert report.summary["evaluated"] == 700
    assert peak <= 8


def test_request_contains_all_applicable_questions_for_one_process(config, snapshot):
    process = snapshot.processes[3]
    request = make_request(snapshot, process, config)
    assert request.process.pid == process.pid
    assert set(request.questions) == {"p7700_JPR001"}


async def test_assessment_callback_streams_before_scan_completes(config, snapshot):
    source = snapshot.model_copy(update={"processes": snapshot.processes[:2]})
    release_slow = asyncio.Event()
    fast_emitted = asyncio.Event()
    emitted = []

    async def handler(request):
        payload = json.loads(request.content)
        pid = payload["state"]["process"]["pid"]
        if pid == 4819:
            await release_slow.wait()
        answers = {
            key: {"type": "noul", "noul": 0.08}
            for key in payload["questions"]
        }
        return httpx.Response(
            200,
            json={
                "model": payload["model"],
                "answers": answers,
                "usage": {"input_tokens": 10, "output_tokens": 1},
            },
        )

    def on_assessment(assessment):
        emitted.append(assessment.process.pid)
        if assessment.process.pid == 3101:
            fast_emitted.set()

    async with JevClient(
        config.jev, "demo", transport=httpx.MockTransport(handler)
    ) as client:
        task = asyncio.create_task(
            Engine(config, client).scan(
                source,
                "demo",
                on_assessment=on_assessment,
            )
        )
        await asyncio.wait_for(fast_emitted.wait(), timeout=1)
        assert not task.done()
        assert 3101 in emitted
        assert 4819 not in emitted
        release_slow.set()
        report = await task

    assert report.summary["evaluated"] == 2
    assert set(emitted) == {3101, 4819}
