import json

import httpx

from jevproc.core.client import JevClient
from jevproc.core.config import CacheSettings
from jevproc.core.demo import demo_transport
from jevproc.core.engine import Engine
from jevproc.core.protocol import make_request
from jevproc.core.storage import AnswerCache


async def test_synthetic_end_to_end_uses_one_request(config,snapshot):
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


async def test_context_rejection_does_not_fragment_snapshot(config,snapshot):
    async with JevClient(config.jev,'demo',transport=httpx.MockTransport(lambda r:httpx.Response(413))) as client:
        report=await Engine(config,client).scan(snapshot,'demo')
    assert report.summary['requests']==1
    assert report.summary['evaluated']==0
    assert report.summary['failed_processes']==4 and report.summary['incomplete']
    assert all(r.status=='not_evaluated' for r in report.assessments)


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


async def test_hundreds_of_processes_are_one_request(config,snapshot):
    processes=[snapshot.processes[0].model_copy(update={'pid':10000+i,'ppid':None}) for i in range(700)]
    source=snapshot.model_copy(update={'processes':processes})
    calls=0
    def handler(request):
        nonlocal calls
        calls+=1
        payload=json.loads(request.content)
        assert 'processes' not in payload['state']
        assert len(payload['questions'])==700
        answers={key:{'type':'noul','noul':0.08} for key in payload['questions']}
        return httpx.Response(200,json={'model':payload['model'],'answers':answers,
                                        'usage':{'input_tokens':1000,'output_tokens':700}})
    async with JevClient(config.jev,'demo',transport=httpx.MockTransport(handler)) as client:
        report=await Engine(config,client).scan(source,'demo')
    assert calls==1 and report.summary['requests']==1
    assert report.summary['evaluated']==700


async def test_missing_evidence_does_not_create_extra_questions(config,snapshot):
    sanitized=snapshot.model_copy(update={'processes':[snapshot.processes[3]]})
    request=make_request(sanitized,sanitized.processes,config)
    assert set(request.questions)=={'p7700_JPR001'}
