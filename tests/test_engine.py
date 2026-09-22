import asyncio
import json

import httpx
import pytest

from jevproc.core.client import JevClient
from jevproc.core.config import CacheSettings, Config
from jevproc.core.demo import demo_transport
from jevproc.core.engine import Engine
from jevproc.core.protocol import make_batch
from jevproc.core.storage import AnswerCache


async def test_synthetic_end_to_end_uses_real_policy(config,snapshot):
    async with JevClient(config.jev,'demo',transport=demo_transport()) as client:
        report=await Engine(config,client).scan(snapshot,'demo')
    assert [r.status for r in report.assessments]==['probably_legitimate','warning','uncertain_warning','unknown']
    assert report.summary['evaluated']==4 and report.summary['requests']==1
    assert report.summary['warnings']==1 and report.summary['uncertain_warnings']==1


async def test_exact_state_cached_and_state_change_invalidates(config,snapshot,tmp_path):
    with AnswerCache(tmp_path/'cache',CacheSettings()) as cache:
        async with JevClient(config.jev,'demo',transport=demo_transport()) as client:
            engine=Engine(config,client,cache)
            first=await engine.scan(snapshot,'demo')
            second=await engine.scan(snapshot,'demo')
            assert first.summary['requests']==1
            assert second.summary['requests']==0 and second.summary['cached_processes']==4
            p=snapshot.processes[0].model_copy(update={'executable':'/different/tool'})
            changed=snapshot.model_copy(update={'processes':[p,*snapshot.processes[1:]]})
            third=await engine.scan(changed,'demo')
            assert third.summary['requests']==1


async def test_context_rejection_splits_without_losing_targets(config,snapshot):
    original=demo_transport()
    def handler(request):
        payload=json.loads(request.content)
        if len(payload['state']['processes'])>1:
            return httpx.Response(413)
        return original.handle_request(request)
    async with JevClient(config.jev,'demo',transport=httpx.MockTransport(handler)) as client:
        report=await Engine(config,client).scan(snapshot,'demo')
    assert report.summary['evaluated']==4
    assert report.summary['requests']==7
    assert not report.summary['incomplete']
    assert len({r.process.pid for r in report.assessments})==4


async def test_single_oversize_request_is_not_hidden_success(config,snapshot):
    async with JevClient(config.jev,'demo',transport=httpx.MockTransport(lambda r:httpx.Response(413))) as client:
        report=await Engine(config,client).scan(snapshot,'demo')
    assert report.summary['evaluated']==0
    assert report.summary['failed_processes']==4 and report.summary['incomplete']


async def test_transport_failure_preserves_all_processes(config,snapshot):
    async with JevClient(config.jev,'demo',transport=httpx.MockTransport(lambda r:httpx.Response(401))) as client:
        report=await Engine(config,client).scan(snapshot,'demo')
    assert len(report.assessments)==4
    assert all(r.status=='not_evaluated' for r in report.assessments)
    assert report.summary['incomplete']


async def test_offline_never_calls_a_client(config,snapshot):
    class Forbidden:
        requests=retries=input_tokens=output_tokens=0
        async def evaluate(self,*args):
            raise AssertionError('network access in offline mode')
    report=await Engine(config,Forbidden()).scan(snapshot,'offline')
    assert report.summary['evaluated']==0 and report.summary['requests']==0
    assert report.summary['not_evaluated']==4
    assert report.summary['warnings']==0


async def test_unstable_identity_not_submitted(config,snapshot):
    p=snapshot.processes[0].model_copy(update={'freshness':'reused'})
    source=snapshot.model_copy(update={'processes':[p]})
    async with JevClient(config.jev,'demo',transport=demo_transport()) as client:
        report=await Engine(config,client).scan(source,'demo')
    assert report.summary['requests']==0
    assert report.summary['unstable_processes']==1


async def test_fixed_worker_pool_limits_concurrency(config,snapshot):
    data=config.model_dump(mode='json')
    data['jev'].update(concurrency=2,batch_size=1)
    config=Config.model_validate(data)
    active=peak=0
    source=demo_transport()
    async def handler(request):
        nonlocal active,peak
        active+=1
        peak=max(peak,active)
        await asyncio.sleep(.005)
        result=source.handle_request(request)
        active-=1
        return result
    async with JevClient(config.jev,'demo',transport=httpx.MockTransport(handler)) as client:
        report=await Engine(config,client).scan(snapshot,'demo')
    assert report.summary['evaluated']==4 and peak==2


async def test_missing_evidence_never_receives_fabricated_negative_answer(config,snapshot):
    sanitized=snapshot.model_copy(update={'processes':[snapshot.processes[3]]})
    batch=make_batch(sanitized,sanitized.processes,config)
    assert set(batch.questions)=={'p7700_JPR001'}
