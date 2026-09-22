import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest
from pydantic import ValidationError

from jevproc.core.collector import _get, _hash_file, _signature, attach_ancestry, attach_network, collect, load_snapshot
from jevproc.core.config import CollectionSettings
from jevproc.core.models import Connection, Process
from jevproc.core.privacy import redact_argv, redact_text, sanitize_snapshot, terminal_text


def test_sensitive_arguments_are_redacted_before_truncation():
    args=["program","--password","SECRET","--api-key=SECOND","https://user:THIRD@example.com/?token=FOURTH",
          "Authorization: Bearer FIFTH","jv_live_abcdefghijk","/Users/alex/private"]
    cleaned,_=redact_argv(args)
    result=" ".join(cleaned)
    for secret in ("SECRET","SECOND","THIRD","FOURTH","FIFTH","abcdefghijk","/Users/alex"):
        assert secret not in result
    assert "<redacted>" in result and "/Users/<user>" in result
    cleaned,truncated=redact_argv(["p","--token="+"z"*10000])
    assert cleaned[1]=="--token=<redacted>" and not truncated


def test_argument_limits_are_explicit():
    args,truncated=redact_argv(["a"]*70)
    assert len(args)==64 and truncated
    args,truncated=redact_argv(["p","x"*1000])
    assert len(args[1]) <=512 and truncated


def test_no_command_line_by_default_on_import(snapshot):
    sanitized=sanitize_snapshot(snapshot,False)
    assert all(p.command_line is None for p in sanitized.processes)
    assert all(p.coverage['command_line']=='not_requested' for p in sanitized.processes)


def test_terminal_control_and_row_injection_escaped():
    raw="safe\x1b[2J\r\nFAKE\u202e\x9b31m"
    escaped=terminal_text(raw)
    assert "\x1b" not in escaped and "\n" not in escaped and "\r" not in escaped and "\u202e" not in escaped
    assert "\\u001b" in escaped


@pytest.mark.parametrize("exception,coverage",[(psutil.AccessDenied(42),'denied'),(psutil.NoSuchProcess(42),'gone'),(OSError(),'unavailable')])
def test_collection_failure_is_not_empty_success(exception,coverage):
    def fail():
        raise exception
    states={}
    assert _get('executable',fail,states) is None
    assert states['executable']==coverage


def test_reused_parent_pid_is_not_attached():
    child=Process(pid=2,created_at=20,ppid=1)
    wrong_parent=Process(pid=1,created_at=30,ppid=0)
    results=attach_ancestry([wrong_parent,child],4)
    assert results[1].ancestors==[]
    assert results[1].coverage['ancestry']=='partial'


def test_ancestry_cycles_and_depth_are_bounded():
    a=Process(pid=1,created_at=1,ppid=2,name='a')
    b=Process(pid=2,created_at=1,ppid=1,name='b')
    results=attach_ancestry([a,b],4)
    assert all(len(p.ancestors)==1 for p in results)
    assert all(p.coverage['ancestry']=='partial' for p in results)


def test_pid_reuse_drops_socket_evidence(monkeypatch):
    process=Process(pid=42,created_at=10,executable='/bin/tool')
    monkeypatch.setattr(psutil,'Process',lambda pid:SimpleNamespace(create_time=lambda:20))
    results=attach_network([process],{42:[Connection(protocol='tcp',remote_address='192.0.2.1',remote_port=443)]},'observed')
    assert results[0].freshness=='reused'
    assert results[0].connections==[]
    assert results[0].coverage['connections']=='unavailable'


def test_hash_is_bounded_regular_file_only(tmp_path):
    path=tmp_path/'binary'
    path.write_bytes(b'abc')
    import hashlib
    assert _hash_file(str(path),3)==(hashlib.sha256(b'abc').hexdigest(),'observed')
    assert _hash_file(str(path),2)==(None,'truncated')
    link=tmp_path/'link'
    link.symlink_to(path)
    assert _hash_file(str(link),100)[0] is None
    fifo=tmp_path/'fifo'
    os.mkfifo(fifo)
    assert _hash_file(str(fifo),100)[0] is None


def test_codesign_never_runs_target_or_shell(monkeypatch):
    import jevproc.core.collector as module
    monkeypatch.setattr(module.sys,'platform','darwin')
    calls=[]
    def run(argv,**kwargs):
        calls.append((argv,kwargs))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.subprocess,'run',run)
    assert _signature('/tmp/a;echo owned')==('valid','observed')
    assert calls[0][0]==['/usr/bin/codesign','--verify','--strict','--','/tmp/a;echo owned']
    assert 'shell' not in calls[0][1]
    assert calls[0][1]['timeout']==3


def test_live_self_inventory_does_not_read_environment_or_cmdline(monkeypatch):
    def forbidden(*args,**kwargs):
        raise AssertionError('sensitive collector used')
    monkeypatch.setattr(psutil.Process,'environ',forbidden)
    monkeypatch.setattr(psutil.Process,'cmdline',forbidden)
    snapshot=collect(CollectionSettings(connections=False),[os.getpid()])
    assert len(snapshot.processes)==1
    p=snapshot.processes[0]
    assert p.pid==os.getpid() and p.created_at is not None
    assert p.command_line is None
    assert p.coverage['connections']=='not_requested'


def test_import_rejects_unknown_fields_and_duplicate_pids(tmp_path,snapshot):
    raw=snapshot.model_dump(mode='json')
    raw['processes'][0]['environment']={'SECRET':'do not send'}
    path=tmp_path/'bad.json'
    import json
    path.write_text(json.dumps(raw))
    with pytest.raises(ValidationError):
        load_snapshot(path)
    raw=snapshot.model_dump(mode='json')
    raw['processes'].append(raw['processes'][0])
    path.write_text(json.dumps(raw))
    with pytest.raises(ValidationError):
        load_snapshot(path)


def test_authorization_split_and_observations_are_redacted(snapshot):
    from jevproc.core.privacy import sanitize_process

    arguments, _ = redact_argv(["curl", "--authorization", "Bearer", "private-token"])
    assert "private-token" not in " ".join(arguments)
    process = snapshot.processes[0].model_copy(update={
        "observations": ["Authorization: Bearer private-token"],
        "name": "a" * 504 + " token=x",
    })
    sanitized = sanitize_process(process, False)
    assert "private-token" not in sanitized.model_dump_json()
    assert len(sanitized.name) <= 512
    assert sanitized.coverage["name"] == "truncated"


def test_exec_image_change_discards_network_evidence(monkeypatch):
    process = Process(pid=42, created_at=10, executable="/bin/original")
    monkeypatch.setattr(psutil, "Process", lambda pid: SimpleNamespace(
        create_time=lambda: 10, exe=lambda: "/bin/replacement",
    ))
    result = attach_network([process], {42: [Connection(protocol="tcp")]}, "observed")[0]
    assert result.freshness == "changed"
    assert result.connections == []


def test_replaced_file_evidence_is_not_combined(tmp_path, monkeypatch):
    import jevproc.core.collector as module

    path = tmp_path / "binary"
    path.write_bytes(b"original")

    def replace_while_hashing(*_args):
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"changed")
        replacement.replace(path)
        return "a" * 64, "observed"

    monkeypatch.setattr(module, "_hash_file", replace_while_hashing)
    info, coverage = module._file_info(str(path), CollectionSettings(hashes=True))
    assert info.sha256 is None
    assert info.mode is None
    assert coverage["file"] == "partial" and coverage["hash"] == "unavailable"
