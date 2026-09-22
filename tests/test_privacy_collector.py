import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest
from pydantic import ValidationError

from jevproc.core.collector import (
    _classify_codesign_failure,
    _family_pids,
    _file_info,
    _get,
    _hash_file,
    _network,
    _parse_lsof_network,
    _resource_usage,
    _signature,
    attach_ancestry,
    attach_children,
    attach_network,
    collect,
    load_snapshot,
)
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


def test_command_line_can_be_explicitly_omitted_on_import(snapshot):
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


def test_codesign_never_runs_target_or_shell_and_parses_identity(monkeypatch):
    import jevproc.core.collector as module
    monkeypatch.setattr(module.sys,'platform','darwin')
    calls=[]
    def run(argv,**kwargs):
        calls.append((argv,kwargs))
        if "--display" in argv:
            return SimpleNamespace(
                returncode=0,
                stdout="",
                stderr=(
                    "Identifier=com.example.tool\n"
                    "TeamIdentifier=TEAM123456\n"
                    "Authority=Developer ID Application: Example Corp\n"
                    "Authority=Developer ID Certification Authority\n"
                ),
            )
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.subprocess,'run',run)
    values, coverage = _signature('/tmp/a;echo owned')
    assert coverage == 'observed'
    assert values == {
        'signature': 'valid',
        'signature_identifier': 'com.example.tool',
        'signature_team_id': 'TEAM123456',
        'signature_authorities': [
            'Developer ID Application: Example Corp',
            'Developer ID Certification Authority',
        ],
    }
    assert calls[0][0]==['/usr/bin/codesign','--verify','--strict','--','/tmp/a;echo owned']
    assert calls[1][0]==['/usr/bin/codesign','--display','--verbose=4','--','/tmp/a;echo owned']
    assert all('shell' not in kwargs for _, kwargs in calls)
    assert all(kwargs['timeout']==3 for _, kwargs in calls)




@pytest.mark.parametrize(
    "diagnostic,state,issue",
    [
        ("resource envelope is obsolete (custom omit rules)", "legacy", "weak_resource_rules"),
        ("resource envelope is obsolete (version 1 signature)", "legacy", "weak_resource_envelope"),
        ("code object is not signed at all", "unsigned", None),
        ("a sealed resource is missing or invalid", "verification_failed", "resource_modified"),
        ("file modified: Contents/Resources/example", "verification_failed", "resource_modified"),
        ("nested code is modified or invalid", "verification_failed", "nested_code_invalid"),
        ("code or signature modified", "verification_failed", "signature_modified"),
        ("does not satisfy its designated Requirement", "verification_failed", "requirement_failed"),
        ("test-requirement: code failed to satisfy specified code requirement(s)", "verification_failed", "requirement_failed"),
        ("bundle format is ambiguous (could be app or framework)", "verification_failed", "bundle_format_invalid"),
        ("bundle format unrecognized, invalid, or unsuitable", "verification_failed", "bundle_format_invalid"),
        ("notarization indicates this code has been revoked", "verification_failed", "revoked"),
        ("CSSMERR_TP_CERT_EXPIRED", "verification_failed", "certificate_expired"),
        ("main executable failed strict validation", "verification_failed", "strict_validation_failed"),
        ("some future codesign diagnostic", "verification_failed", "other"),
    ],
)
def test_codesign_failure_diagnostics_are_normalized(diagnostic, state, issue):
    assert _classify_codesign_failure(diagnostic) == (state, issue)


def test_legacy_codesign_keeps_signer_metadata(monkeypatch):
    import jevproc.core.collector as module

    monkeypatch.setattr(module.sys, "platform", "darwin")
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if "--verify" in argv:
            return SimpleNamespace(
                returncode=1,
                stderr=(
                    "/Library/Apple/System/Library/CoreServices/XProtect.app/"
                    "Contents/XPCServices/XProtectPluginService.xpc: "
                    "resource envelope is obsolete (custom omit rules)\n"
                ),
            )
        return SimpleNamespace(
            returncode=0,
            stdout="",
            stderr=(
                "Identifier=com.apple.XProtectPluginService\n"
                "TeamIdentifier=Software Signing\n"
                "Authority=Software Signing\n"
                "Authority=Apple Code Signing Certification Authority\n"
            ),
        )

    monkeypatch.setattr(module.subprocess, "run", run)
    values, coverage = _signature("/Library/Apple/System/Library/CoreServices/XProtect")
    assert coverage == "observed"
    assert values == {
        "signature": "legacy",
        "signature_issue": "weak_resource_rules",
        "signature_identifier": "com.apple.XProtectPluginService",
        "signature_team_id": "Software Signing",
        "signature_authorities": [
            "Software Signing",
            "Apple Code Signing Certification Authority",
        ],
    }
    assert len(calls) == 2
    assert calls[0][0][:3] == ["/usr/bin/codesign", "--verify", "--strict"]
    assert calls[1][0][:3] == ["/usr/bin/codesign", "--display", "--verbose=4"]
    assert all("shell" not in kwargs for _, kwargs in calls)


def test_unsigned_codesign_skips_display(monkeypatch):
    import jevproc.core.collector as module

    monkeypatch.setattr(module.sys, "platform", "darwin")
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=1, stderr="code object is not signed at all")

    monkeypatch.setattr(module.subprocess, "run", run)
    values, coverage = _signature("/tmp/unsigned")
    assert coverage == "observed"
    assert values == {"signature": "unsigned"}
    assert calls == [["/usr/bin/codesign", "--verify", "--strict", "--", "/tmp/unsigned"]]


def test_failed_codesign_can_preserve_display_identity(monkeypatch):
    import jevproc.core.collector as module

    monkeypatch.setattr(module.sys, "platform", "darwin")

    def run(argv, **kwargs):
        if "--verify" in argv:
            return SimpleNamespace(returncode=1, stderr="code or signature modified")
        return SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="Identifier=com.example.tool\nTeamIdentifier=TEAM123456\n",
        )

    monkeypatch.setattr(module.subprocess, "run", run)
    values, coverage = _signature("/tmp/tool")
    assert coverage == "observed"
    assert values["signature"] == "verification_failed"
    assert values["signature_issue"] == "signature_modified"
    assert values["signature_identifier"] == "com.example.tool"
    assert values["signature_team_id"] == "TEAM123456"



def test_live_self_inventory_does_not_read_environment_or_cmdline(monkeypatch):
    def forbidden(*args,**kwargs):
        raise AssertionError('sensitive collector used')
    monkeypatch.setattr(psutil.Process,'environ',forbidden)
    monkeypatch.setattr(psutil.Process,'cmdline',forbidden)
    snapshot=collect(
        CollectionSettings(
            connections=False,
            command_line=False,
            hashes=False,
            signatures=False,
        ),
        [os.getpid()],
    )
    assert len(snapshot.processes)==1
    p=snapshot.processes[0]
    assert p.pid==os.getpid() and p.created_at is not None
    assert p.command_line is None
    assert p.coverage['connections']=='not_requested'





def test_collect_reports_selected_process_progress():
    events = []
    snapshot = collect(
        CollectionSettings(
            ancestry_depth=0,
            connections=False,
            command_line=False,
            hashes=False,
            signatures=False,
            resources=False,
            child_limit=0,
        ),
        [os.getpid()],
        on_progress=lambda completed, total: events.append((completed, total)),
    )
    assert len(snapshot.processes) == 1
    assert events == [(0, 1), (1, 1)]


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


def test_lsof_field_parser_maps_tcp_and_udp_connections():
    parsed = _parse_lsof_network(
        "\n".join([
            "p42",
            "ctool",
            "f9",
            "PTCP",
            "n127.0.0.1:51000->198.51.100.7:443",
            "TST=ESTABLISHED",
            "f10",
            "PUDP",
            "n*:5353",
            "p43",
            "ctool2",
            "f4",
            "PTCP",
            "n[::1]:8000",
            "TST=LISTEN",
        ])
    )
    assert parsed[42][0] == Connection(
        protocol="tcp",
        local_address="127.0.0.1",
        local_port=51000,
        remote_address="198.51.100.7",
        remote_port=443,
        status="ESTABLISHED",
    )
    assert parsed[42][1].protocol == "udp"
    assert parsed[42][1].local_address == ""
    assert parsed[42][1].local_port == 5353
    assert parsed[43][0].local_address == "::1"
    assert parsed[43][0].local_port == 8000
    assert parsed[43][0].status == "LISTEN"


def test_macos_network_falls_back_to_lsof(monkeypatch):
    import jevproc.core.collector as module

    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(
        module.psutil,
        "net_connections",
        lambda **kwargs: (_ for _ in ()).throw(psutil.AccessDenied()),
    )
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout="p42\nf9\nPTCP\nn127.0.0.1:5000->203.0.113.5:443\nTST=ESTABLISHED\n",
        )
    monkeypatch.setattr(module.subprocess, "run", run)
    network, coverage = _network(CollectionSettings())
    assert coverage == "partial"
    assert network[42][0].remote_address == "203.0.113.5"
    assert calls[0][0] == ["/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP", "-FpcfnPT"]
    assert "shell" not in calls[0][1]


def test_file_inspection_cache_deduplicates_hash_and_signature(tmp_path, monkeypatch):
    import jevproc.core.collector as module

    path = tmp_path / "binary"
    path.write_bytes(b"same executable")
    calls = {"hash": 0, "signature": 0}

    def fake_hash(*_args):
        calls["hash"] += 1
        return "a" * 64, "observed"

    def fake_signature(*_args):
        calls["signature"] += 1
        return {
            "signature": "valid",
            "signature_identifier": "com.example.binary",
            "signature_team_id": "TEAM123456",
            "signature_authorities": ["Example Authority"],
        }, "observed"

    monkeypatch.setattr(module, "_hash_file", fake_hash)
    monkeypatch.setattr(module, "_signature", fake_signature)
    settings = CollectionSettings(hashes=True, signatures=True)
    cache = {}
    first = _file_info(str(path), settings, cache)
    second = _file_info(str(path), settings, cache)
    assert first == second
    assert calls == {"hash": 1, "signature": 1}
    assert first[0].sha256 == "a" * 64
    assert first[0].signature_identifier == "com.example.binary"


def test_resource_usage_collects_short_sample_context():
    proc = SimpleNamespace(
        cpu_percent=lambda interval=None: 87.5,
        memory_info=lambda: SimpleNamespace(rss=3 * 1024 * 1024 * 1024),
        memory_percent=lambda: 12.5,
        num_threads=lambda: 42,
        num_fds=lambda: 99,
    )
    resources, coverage = _resource_usage(proc, cpu_primed=True)
    assert coverage == "observed"
    assert resources.cpu_percent == 87.5
    assert resources.rss_bytes == 3 * 1024 * 1024 * 1024
    assert resources.memory_percent == 12.5
    assert resources.thread_count == 42
    assert resources.fd_count == 99


def test_resource_usage_is_partial_when_one_measure_is_denied():
    proc = SimpleNamespace(
        cpu_percent=lambda interval=None: 10.0,
        memory_info=lambda: SimpleNamespace(rss=128 * 1024 * 1024),
        memory_percent=lambda: 1.2,
        num_threads=lambda: 8,
        num_fds=lambda: (_ for _ in ()).throw(psutil.AccessDenied()),
    )
    resources, coverage = _resource_usage(proc, cpu_primed=True)
    assert coverage == "partial"
    assert resources.cpu_percent == 10.0
    assert resources.fd_count is None


def test_children_are_bounded_and_total_count_is_preserved(monkeypatch):
    import jevproc.core.collector as module
    from jevproc.core.models import Child

    children = [
        Child(pid=100 + index, created_at=10 + index, name=f"child-{index}")
        for index in range(5)
    ]
    monkeypatch.setattr(module, "_child_index", lambda: ({42: children}, "observed"))
    process = Process(pid=42, created_at=1)
    result = attach_children([process], 2)[0]
    assert [child.pid for child in result.children] == [100, 101]
    assert result.child_count == 5
    assert result.coverage["children"] == "truncated"


def test_family_selection_walks_descendants_only(monkeypatch):
    import jevproc.core.collector as module

    table = [
        SimpleNamespace(info={"pid": 1, "ppid": 0}),
        SimpleNamespace(info={"pid": 10, "ppid": 1}),
        SimpleNamespace(info={"pid": 11, "ppid": 10}),
        SimpleNamespace(info={"pid": 12, "ppid": 10}),
        SimpleNamespace(info={"pid": 13, "ppid": 11}),
        SimpleNamespace(info={"pid": 20, "ppid": 1}),
    ]
    monkeypatch.setattr(module.psutil, "pid_exists", lambda pid: pid in {1, 10, 11, 12, 13, 20})
    monkeypatch.setattr(module.psutil, "process_iter", lambda *args, **kwargs: iter(table))
    assert _family_pids(10) == [10, 11, 12, 13]


def test_live_missing_parent_can_be_resolved_for_single_pid(monkeypatch):
    import jevproc.core.collector as module

    child = Process(pid=42, created_at=20, ppid=7, name="child")
    parent_proc = SimpleNamespace(
        create_time=lambda: 10,
        name=lambda: "parent",
        exe=lambda: "/bin/parent",
        ppid=lambda: 1,
    )
    grandparent_proc = SimpleNamespace(
        create_time=lambda: 1,
        name=lambda: "launchd",
        exe=lambda: "/sbin/launchd",
        ppid=lambda: 0,
    )
    monkeypatch.setattr(
        module.psutil,
        "Process",
        lambda pid: parent_proc if pid == 7 else grandparent_proc,
    )
    result = attach_ancestry([child], 4, resolve_missing=True)[0]
    assert [parent.pid for parent in result.ancestors] == [7, 1]
    assert result.coverage["ancestry"] == "observed"
