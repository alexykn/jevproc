import io
import json
import os
import subprocess
import sys

import pytest
from wcwidth import wcswidth

from jevproc.cli.main import exit_code, main
from jevproc.cli.render import Reporter, Terminal, render
from jevproc.core.client import JevClient
from jevproc.core.demo import demo_transport
from jevproc.core.engine import Engine
from jevproc.core.models import Child, ResourceUsage


@pytest.fixture
async def report(config,snapshot):
    async with JevClient(config.jev,'demo',transport=demo_transport()) as client:
        return await Engine(config,client).scan(snapshot,'demo')


def test_default_only_warning_and_uncertain_warning_processes(report):
    stream=io.StringIO()
    render(report,stream,color='never')
    text=stream.getvalue()
    assert 'system-update' in text and 'build-helper' in text
    assert 'backup-worker' not in text and 'restricted-worker' not in text
    assert '[uncertain warning]' in text and '\x1b' not in text


def test_verbose_includes_other_processes(report):
    stream=io.StringIO()
    render(report,stream,verbose=True,color='never')
    assert all(name in stream.getvalue() for name in ('system-update','build-helper','backup-worker','restricted-worker'))


def test_machine_output_is_complete_even_without_verbose(report):
    stream=io.StringIO()
    render(report,stream,format_name='json')
    data=json.loads(stream.getvalue())
    assert len(data['assessments'])==4 and data['schema_version']==1
    stream=io.StringIO()
    render(report,stream,format_name='jsonl')
    events=[json.loads(line) for line in stream.getvalue().splitlines()]
    assert [e['event'] for e in events]==['start','process','process','process','process','summary']


@pytest.mark.parametrize('width',[20,24,40,80])
def test_terminal_wraps_long_and_unicode_evidence(report,width):
    stream=io.StringIO()
    render(report,stream,verbose=True,width=width,color='never')
    assert all(wcswidth(line)<=width for line in stream.getvalue().splitlines())
    stream=io.StringIO()
    Terminal(stream,width=width,color='never').line('界'*80+' e\u0301'*30,indent=8,following=10)
    assert all(wcswidth(line)<=width for line in stream.getvalue().splitlines())


def test_no_color_overrides_forced_color(monkeypatch):
    monkeypatch.setenv('NO_COLOR','1')
    stream=io.StringIO()
    Terminal(stream,color='always').line('test',style='\x1b[31m')
    assert stream.getvalue()=='test\n'


def test_exit_codes(report):
    assert exit_code(report,'warning')==1
    assert exit_code(report,'none')==0
    uncertain=report.model_copy(update={'summary':{**report.summary,'warnings':0}})
    assert exit_code(uncertain,'warning')==0 and exit_code(uncertain,'any')==1
    incomplete=report.model_copy(update={'summary':{**report.summary,'incomplete':True}})
    assert exit_code(incomplete,'none')==2


def test_demo_cli_has_no_key_requirement(capsys,monkeypatch):
    monkeypatch.delenv('TYPESAFE_API_KEY',raising=False)
    assert main(['--demo','--format','json','--fail-on','none'])==0
    data=json.loads(capsys.readouterr().out)
    assert data['mode']=='demo' and data['summary']['synthetic']


def test_missing_api_key_fails_before_collection(capsys,monkeypatch):
    import jevproc.cli.main as module
    monkeypatch.delenv('TYPESAFE_API_KEY',raising=False)
    monkeypatch.setattr(module,'collect',lambda *a:pytest.fail('should fail before collecting'))
    assert main([])==2
    assert 'TYPESAFE_API_KEY' in capsys.readouterr().err


def test_live_offline_cli_smoke(capsys):
    assert main([
        '--offline',
        '--pid',
        str(os.getpid()),
        '--no-command-line',
        '--no-connections',
        '--no-hashes',
        '--no-signatures',
        '--no-resources',
        '--format',
        'json',
    ])==0
    data=json.loads(capsys.readouterr().out)
    assert data['summary']['requests']==0 and data['summary']['evaluated']==0
    assert data['assessments'][0]['process']['command_line'] is None


def test_resources_and_children_are_json_only_not_text(report):
    process = report.assessments[0].process.model_copy(update={
        "resources": ResourceUsage(
            cpu_percent=88.0,
            rss_bytes=3221225472,
            memory_percent=12.5,
            thread_count=42,
            fd_count=99,
        ),
        "children": [
            Child(
                pid=99999,
                created_at=1790071000.0,
                name="worker-child",
                executable="/tmp/worker-child",
                status="running",
            )
        ],
        "child_count": 1,
    })
    assessment = report.assessments[0].model_copy(update={"process": process})
    changed = report.model_copy(update={"assessments": [assessment]})

    stream = io.StringIO()
    render(changed, stream, verbose=True, color="never")
    text = stream.getvalue()
    assert "88.0" not in text
    assert "3221225472" not in text
    assert "worker-child" not in text

    stream = io.StringIO()
    render(changed, stream, format_name="json")
    payload = json.loads(stream.getvalue())
    evidence = payload["assessments"][0]["process"]
    assert evidence["resources"]["cpu_percent"] == 88.0
    assert evidence["children"][0]["name"] == "worker-child"


def test_invalid_input_errors_do_not_echo_secrets(tmp_path,capsys):
    path=tmp_path/'bad.json'
    path.write_text('{"secret":"PRIVATE-EXAMPLE-TOKEN"}')
    assert main(['--offline','--input',str(path)])==2
    assert 'PRIVATE-EXAMPLE-TOKEN' not in capsys.readouterr().err


@pytest.mark.parametrize('args',[
    ['--watch','nan'],
    ['--watch','inf'],
    ['--watch','0'],
    ['--demo','--watch','1'],
    ['--pid','-1'],
    ['--pid','1','--family','1'],
])
def test_bad_cli_combinations_rejected(args):
    with pytest.raises(SystemExit) as exc:
        main(args)
    assert exc.value.code==2





def test_reporter_prints_visible_process_before_summary(report):
    stream = io.StringIO()
    reporter = Reporter(
        stream,
        mode=report.mode,
        snapshot_time=report.snapshot_time,
        model_requested=report.model_requested,
        synthetic=report.summary["synthetic"],
        total_processes=report.summary["processes"],
        color="never",
    )
    warning = next(item for item in report.assessments if item.status == "warning")
    reporter.emit(warning)
    partial = stream.getvalue()
    assert "system-update" in partial
    assert "Warnings:" not in partial

    reporter.finish(report)
    assert "Warnings:" in stream.getvalue()


def test_jsonl_reporter_flushes_process_event_before_summary(report):
    stream = io.StringIO()
    reporter = Reporter(
        stream,
        mode=report.mode,
        snapshot_time=report.snapshot_time,
        model_requested=report.model_requested,
        synthetic=report.summary["synthetic"],
        total_processes=report.summary["processes"],
        format_name="jsonl",
    )
    reporter.emit(report.assessments[0])
    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert [event["event"] for event in events] == ["start", "process"]

    reporter.finish(report)
    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert events[-1]["event"] == "summary"
