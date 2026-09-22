"""Read-only Linux/macOS snapshots. No target execution, memory reads or network probes."""

import hashlib
import os
import platform
import socket
import stat
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable

import psutil

from jevproc.core.config import CollectionSettings
from jevproc.core.models import (
    Child,
    Connection,
    Coverage,
    Executable,
    Host,
    Parent,
    Process,
    ResourceUsage,
    Snapshot,
)
from jevproc.core.privacy import redact_argv, sanitize_snapshot


class CollectionError(RuntimeError):
    pass


def _get(field: str, action: Callable[[], Any], coverage: dict[str, Coverage], default: Any = None) -> Any:
    try:
        value = action()
        coverage[field] = "observed"
        return value
    except psutil.AccessDenied:
        coverage[field] = "denied"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        coverage[field] = "gone"
    except (OSError, NotImplementedError):
        coverage[field] = "unavailable"
    return default


def _endpoint(text: str) -> tuple[str, int]:
    """Parse one numeric lsof endpoint without DNS/service-name ambiguity."""
    value = text.strip()
    if " (" in value:
        value = value.rsplit(" (", 1)[0]
    if value.startswith("["):
        marker = value.rfind("]:")
        if marker >= 0:
            host, port = value[1:marker], value[marker + 2:]
        else:
            return value[:512], 0
    else:
        host, separator, port = value.rpartition(":")
        if not separator:
            return value[:512], 0
    if not port.isdigit():
        return value[:512], 0
    return ("" if host == "*" else host[:512], int(port))


def _parse_lsof_network(output: str) -> dict[int, list[Connection]]:
    """Parse lsof field output; f records delimit sockets and p records delimit processes."""
    by_pid: dict[int, list[Connection]] = defaultdict(list)
    pid: int | None = None
    protocol = ""
    endpoint = ""
    status = ""

    def flush() -> None:
        nonlocal protocol, endpoint, status
        if pid is not None and protocol in {"TCP", "UDP"} and endpoint:
            local_text, arrow, remote_text = endpoint.partition("->")
            local_address, local_port = _endpoint(local_text)
            remote_address, remote_port = _endpoint(remote_text) if arrow else ("", 0)
            by_pid[pid].append(Connection(
                protocol=protocol.lower(),
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                status=status[:512],
            ))
        protocol = endpoint = status = ""

    for line in output.splitlines():
        if not line:
            continue
        field, value = line[0], line[1:]
        if field == "p":
            flush()
            try:
                pid = int(value)
            except ValueError:
                pid = None
        elif field == "f":
            flush()
        elif field == "P":
            protocol = value.upper()
        elif field == "n":
            endpoint = value
        elif field == "T" and value.startswith("ST="):
            status = value[3:]
    flush()

    result: dict[int, list[Connection]] = {}
    for owner, entries in by_pid.items():
        unique = {
            (c.protocol, c.local_address, c.local_port, c.remote_address, c.remote_port, c.status): c
            for c in entries
        }
        result[owner] = sorted(
            unique.values(),
            key=lambda c: (
                c.protocol, c.local_address, c.local_port,
                c.remote_address, c.remote_port, c.status,
            ),
        )
    return result


def _lsof_network() -> tuple[dict[int, list[Connection]], Coverage]:
    """Best-effort macOS fallback when psutil cannot enumerate system sockets unprivileged."""
    try:
        result = subprocess.run(
            ["/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP", "-FpcfnPT"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}, "unavailable"
    if result.returncode not in {0, 1}:
        return {}, "unavailable"
    # An unprivileged lsof view is useful but not guaranteed complete for every other UID.
    return _parse_lsof_network(result.stdout), "partial"


def _network(settings: CollectionSettings) -> tuple[dict[int, list[Connection]], Coverage]:
    if not settings.connections:
        return {}, "not_requested"
    try:
        sockets = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        if sys.platform == "darwin":
            return _lsof_network()
        return {}, "denied"
    except (OSError, NotImplementedError):
        return {}, "unavailable"
    by_pid: dict[int, list[Connection]] = defaultdict(list)
    # Linux may silently omit inaccessible entries. Even root sees a point-in-time snapshot,
    # not a complete history, and sockets with no owner remain unattributed.
    incomplete = os.geteuid() != 0 or any(item.pid is None for item in sockets)
    for item in sockets:
        if item.pid is None:
            continue
        by_pid[item.pid].append(Connection(
            protocol="tcp" if item.type == socket.SOCK_STREAM else "udp",
            local_address=item.laddr.ip if item.laddr else "",
            local_port=item.laddr.port if item.laddr else 0,
            remote_address=item.raddr.ip if item.raddr else "",
            remote_port=item.raddr.port if item.raddr else 0,
            status=item.status,
        ))
    for entries in by_pid.values():
        entries.sort(key=lambda c: (c.protocol, c.local_address, c.local_port, c.remote_address, c.remote_port))
    return dict(by_pid), "partial" if incomplete else "observed"


def _hash_file(path: str, max_bytes: int) -> tuple[str | None, Coverage]:
    """Do not follow a final symlink or block on a FIFO/device substituted for a file."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                return None, "unavailable"
            if before.st_size > max_bytes:
                return None, "truncated"
            digest = hashlib.sha256()
            remaining = max_bytes + 1
            while remaining:
                block = handle.read(min(1024 * 1024, remaining))
                if not block:
                    break
                digest.update(block)
                remaining -= len(block)
            if remaining == 0:
                return None, "truncated"
            after = os.fstat(handle.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                return None, "partial"
            return digest.hexdigest(), "observed"
    except PermissionError:
        return None, "denied"
    except OSError:
        return None, "unavailable"


def _classify_codesign_failure(stderr: str) -> tuple[str, str | None]:
    """Normalize stable Security.framework/codesign diagnostics into bounded evidence."""
    text = stderr.lower()

    # These are legacy signature formats/resource rules, not evidence that code was modified.
    if "resource envelope is obsolete (custom omit rules)" in text:
        return "legacy", "weak_resource_rules"
    if "resource envelope is obsolete (version 1 signature)" in text:
        return "legacy", "weak_resource_envelope"

    if "code object is not signed" in text:
        return "unsigned", None

    # Integrity failures: prefer the most specific observed condition.
    if (
        "a sealed resource is missing or invalid" in text
        or "sealed resource is missing or invalid" in text
        or "invalid resource directory" in text
        or "resource modified:" in text
        or "resource missing:" in text
        or "resource added:" in text
        or "file modified:" in text
        or "file missing:" in text
        or "file added:" in text
    ):
        return "verification_failed", "resource_modified"
    if (
        "nested code is modified or invalid" in text
        or "embedded framework contains modified or invalid version" in text
        or "nested code is unsigned" in text
    ):
        return "verification_failed", "nested_code_invalid"
    if "code or signature modified" in text:
        return "verification_failed", "signature_modified"

    # Requirement, trust, and format failures are distinct from content modification.
    if (
        "does not satisfy its designated requirement" in text
        or "failed to satisfy one of the code requirements" in text
        or "code failed to satisfy specified code requirement" in text
    ):
        return "verification_failed", "requirement_failed"
    if (
        "notarization indicates this code has been revoked" in text
        or "cssmerr_tp_cert_revoked" in text
        or "certificate was revoked" in text
    ):
        return "verification_failed", "revoked"
    if (
        "cssmerr_tp_cert_expired" in text
        or "certificate has expired" in text
        or "certificate expired" in text
    ):
        return "verification_failed", "certificate_expired"
    if (
        "bundle format is ambiguous" in text
        or "bundle format unrecognized, invalid, or unsuitable" in text
        or "object file format invalid or unsuitable" in text
        or "required information property list" in text
    ):
        return "verification_failed", "bundle_format_invalid"
    if (
        "main executable failed strict validation" in text
        or "unsealed contents present" in text
        or "invalid destination for symbolic link in bundle" in text
        or "unsupported resource found" in text
        or "must be a regular file" in text
    ):
        return "verification_failed", "strict_validation_failed"

    return "verification_failed", "other"


def _signature(path: str) -> tuple[dict[str, Any], Coverage]:
    if sys.platform != "darwin":
        return {"signature": "unavailable"}, "unavailable"
    try:
        verify = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", "--", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"signature": "unavailable"}, "unavailable"

    if verify.returncode == 0:
        values: dict[str, Any] = {"signature": "valid"}
    else:
        state, issue = _classify_codesign_failure(getattr(verify, "stderr", "") or "")
        values = {"signature": state}
        if issue is not None:
            values["signature_issue"] = issue
        if state == "unsigned":
            return values, "observed"

    # Display metadata is useful provenance even when integrity verification failed
    # or the signature uses a legacy resource envelope. It does not make the
    # verification result valid.
    try:
        display = subprocess.run(
            ["/usr/bin/codesign", "--display", "--verbose=4", "--", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return values, "observed"

    authorities: list[str] = []
    text = (getattr(display, "stdout", "") or "") + "\n" + (getattr(display, "stderr", "") or "")
    for line in text.splitlines():
        if line.startswith("Identifier="):
            values["signature_identifier"] = line.split("=", 1)[1][:512]
        elif line.startswith("TeamIdentifier="):
            team = line.split("=", 1)[1]
            if team and team != "not set":
                values["signature_team_id"] = team[:512]
        elif line.startswith("Authority=") and len(authorities) < 8:
            authorities.append(line.split("=", 1)[1][:512])
    values["signature_authorities"] = authorities
    # Verification and display are separate evidence: metadata never upgrades
    # a legacy or failed verification result to valid.
    return values, "observed"


def _file_info(
    path: str | None,
    settings: CollectionSettings,
    cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] | None = None,
) -> tuple[Executable, dict[str, Coverage]]:
    coverage: dict[str, Coverage] = {
        "file": "unavailable",
        "hash": "unavailable" if settings.hashes else "not_requested",
        "signature": "unavailable" if settings.signatures else "not_requested",
    }
    if not path or not os.path.isabs(path) or "\x00" in path:
        return Executable(), coverage

    values: dict[str, Any] = {}
    before = None
    cache_key = None
    regular = False
    try:
        info = os.stat(path)
        regular = stat.S_ISREG(info.st_mode)
        before = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        cache_key = (
            path,
            *before,
            settings.hashes,
            settings.signatures,
            settings.max_hash_bytes,
        )
        if cache is not None and cache_key in cache:
            cached_info, cached_coverage = cache[cache_key]
            return cached_info, dict(cached_coverage)
        values = {
            "exists": True,
            "size": info.st_size,
            "mode": stat.S_IMODE(info.st_mode),
            "owner_uid": info.st_uid,
            "modified_ns": info.st_mtime_ns,
        }
        coverage["file"] = "observed"
    except FileNotFoundError:
        values["exists"] = False
        coverage["file"] = "observed"
    except PermissionError:
        coverage["file"] = "denied"
    except OSError:
        pass

    if values.get("exists") is True and regular:
        if settings.hashes:
            values["sha256"], coverage["hash"] = _hash_file(path, settings.max_hash_bytes)
        if settings.signatures:
            signature_values, coverage["signature"] = _signature(path)
            values.update(signature_values)

    if before is not None and (settings.hashes or settings.signatures):
        try:
            info = os.stat(path)
            after = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        except OSError:
            after = None
        if before != after:
            # Do not combine metadata and expensive inspection from different files.
            coverage["file"] = "partial"
            if settings.hashes:
                coverage["hash"] = "unavailable"
            if settings.signatures:
                coverage["signature"] = "unavailable"
            return Executable(), coverage

    result = Executable.model_validate(values)
    if cache is not None and cache_key is not None and coverage["file"] == "observed":
        cache[cache_key] = (result, dict(coverage))
    return result, coverage

def _resource_value(action: Callable[[], Any]) -> tuple[Any, Coverage]:
    try:
        return action(), "observed"
    except psutil.AccessDenied:
        return None, "denied"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None, "gone"
    except (OSError, NotImplementedError, AttributeError):
        return None, "unavailable"


def _resource_usage(proc: psutil.Process, cpu_primed: bool) -> tuple[ResourceUsage, Coverage]:
    values: dict[str, Any] = {}
    states: list[Coverage] = []

    if cpu_primed:
        value, state = _resource_value(lambda: proc.cpu_percent(interval=None))
        values["cpu_percent"] = value
        states.append(state)
    else:
        values["cpu_percent"] = None
        states.append("unavailable")

    memory_info, state = _resource_value(proc.memory_info)
    values["rss_bytes"] = memory_info.rss if memory_info is not None else None
    states.append(state)

    value, state = _resource_value(proc.memory_percent)
    values["memory_percent"] = value
    states.append(state)

    value, state = _resource_value(proc.num_threads)
    values["thread_count"] = value
    states.append(state)

    value, state = _resource_value(proc.num_fds)
    values["fd_count"] = value
    states.append(state)

    observed = sum(state == "observed" for state in states)
    if observed == len(states):
        coverage: Coverage = "observed"
    elif observed:
        coverage = "partial"
    elif "denied" in states:
        coverage = "denied"
    elif "gone" in states:
        coverage = "gone"
    else:
        coverage = "unavailable"
    return ResourceUsage.model_validate(values), coverage


def _prime_resource_probes(
    pids: list[int], settings: CollectionSettings
) -> dict[int, psutil.Process]:
    if not settings.resources:
        return {}
    probes: dict[int, psutil.Process] = {}
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            proc.cpu_percent(interval=None)
            probes[pid] = proc
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            continue
    if probes:
        time.sleep(settings.resource_sample_seconds)
    return probes


def _darwin_comm_table() -> dict[int, str]:
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,comm="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if result.returncode != 0:
        return {}
    table: dict[int, str] = {}
    for line in result.stdout.splitlines():
        value = line.strip()
        if not value:
            continue
        pid_text, separator, command = value.partition(" ")
        if not separator or not pid_text.isdigit():
            continue
        command = command.strip()
        if command:
            table[int(pid_text)] = command[:8192]
    return table


def _darwin_comm(pid: int) -> str | None:
    try:
        result = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "comm="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip() if result.returncode == 0 else ""
    return value[:8192] or None


def _process_name_without_cmdline(
    proc: psutil.Process,
    pid: int,
    darwin_comm: str | None = None,
) -> str:
    try:
        if sys.platform == "linux":
            with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as handle:
                return handle.read(513).strip()[:512] or "<unavailable>"
        if sys.platform == "darwin":
            value = darwin_comm or _darwin_comm(pid)
            return os.path.basename(value)[:512] if value else "<unavailable>"
        return proc.name()[:512]
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return "<unavailable>"


def _process_executable_without_cmdline(
    proc: psutil.Process,
    pid: int,
    darwin_comm: str | None = None,
) -> str | None:
    try:
        if sys.platform == "linux":
            value = os.readlink(f"/proc/{pid}/exe")
            if value.endswith(" (deleted)"):
                value = value[:-10]
            return value[:8192] or None
        if sys.platform == "darwin":
            value = darwin_comm or _darwin_comm(pid)
            return value[:8192] if value else None
        value = proc.exe() or None
        return value[:8192] if value else None
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return None


def _child_index() -> tuple[dict[int, list[Child]], Coverage]:
    by_parent: dict[int, list[Child]] = defaultdict(list)
    incomplete = False
    darwin_commands = _darwin_comm_table() if sys.platform == "darwin" else {}
    try:
        iterator = psutil.process_iter(
            ["pid", "ppid", "create_time", "status"],
            ad_value=None,
        )
        for item in iterator:
            info = item.info
            ppid = info.get("ppid")
            pid = info.get("pid")
            if ppid is None or pid is None:
                incomplete = True
                continue
            pid = int(pid)
            darwin_comm = darwin_commands.get(pid)
            name = _process_name_without_cmdline(item, pid, darwin_comm)
            executable = _process_executable_without_cmdline(item, pid, darwin_comm)
            status = info.get("status") or "unknown"
            created = info.get("create_time")
            if created is None or executable is None or name == "<unavailable>":
                incomplete = True
            by_parent[int(ppid)].append(Child(
                pid=pid,
                created_at=created,
                name=name,
                executable=executable,
                status=str(status)[:512],
            ))
    except (OSError, NotImplementedError):
        return {}, "unavailable"
    for entries in by_parent.values():
        entries.sort(key=lambda child: (child.created_at or 0, child.pid))
    return dict(by_parent), "partial" if incomplete else "observed"


def _attach_children_from_index(
    processes: list[Process],
    limit: int,
    by_parent: dict[int, list[Child]],
    global_coverage: Coverage,
) -> list[Process]:
    if limit == 0:
        return [
            process.model_copy(update={
                "children": [],
                "child_count": 0,
                "coverage": {**process.coverage, "children": "not_requested"},
            })
            for process in processes
        ]
    result = []
    for process in processes:
        entries = by_parent.get(process.pid, [])
        state = global_coverage
        if process.freshness != "observed":
            entries, state = [], "unavailable"
        elif len(entries) > limit:
            state = "truncated"
        result.append(process.model_copy(update={
            "children": entries[:limit],
            "child_count": len(entries),
            "coverage": {**process.coverage, "children": state},
        }))
    return result


def attach_children(processes: list[Process], limit: int) -> list[Process]:
    if limit == 0:
        return _attach_children_from_index(processes, limit, {}, "not_requested")
    by_parent, global_coverage = _child_index()
    return _attach_children_from_index(processes, limit, by_parent, global_coverage)


def _family_pids(root_pid: int) -> list[int]:
    if not psutil.pid_exists(root_pid):
        raise CollectionError(f"process family root PID {root_pid} does not exist")
    children: dict[int, list[int]] = defaultdict(list)
    seen_pids = set()
    try:
        for item in psutil.process_iter(["pid", "ppid"], ad_value=None):
            pid = item.info.get("pid")
            ppid = item.info.get("ppid")
            if pid is None:
                continue
            seen_pids.add(int(pid))
            if ppid is not None:
                children[int(ppid)].append(int(pid))
    except (OSError, NotImplementedError) as exc:
        raise CollectionError("could not enumerate process family") from exc

    if root_pid not in seen_pids and not psutil.pid_exists(root_pid):
        raise CollectionError(f"process family root PID {root_pid} exited")

    ordered = [root_pid]
    seen = {root_pid}
    cursor = 0
    while cursor < len(ordered):
        parent = ordered[cursor]
        cursor += 1
        for child in sorted(children.get(parent, [])):
            if child not in seen:
                seen.add(child)
                ordered.append(child)
    return ordered


def _age_band(created: float | None, now: float) -> str:
    if created is None or created > now:
        return "unknown"
    age = now - created
    return "under_minute" if age < 60 else "under_hour" if age < 3600 else "under_day" if age < 86400 else "older"


def _process(
    pid: int,
    settings: CollectionSettings,
    now: float,
    file_cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] | None = None,
    resource_probe: psutil.Process | None = None,
) -> Process:
    try:
        proc = resource_probe or psutil.Process(pid)
    except psutil.NoSuchProcess:
        return Process(pid=pid, freshness="gone", coverage={"identity": "gone"})
    coverage: dict[str, Coverage] = {}
    oneshot = proc.oneshot() if hasattr(proc, "oneshot") else nullcontext()
    with oneshot:
        created = _get("identity", proc.create_time, coverage)
        if settings.command_line:
            name = _get("name", proc.name, coverage, "<unavailable>")
            executable = _get("executable", proc.exe, coverage) or None
        else:
            name = _process_name_without_cmdline(proc, pid)
            executable = _process_executable_without_cmdline(proc, pid)
            coverage["name"] = "observed" if name != "<unavailable>" else "unavailable"
            coverage["executable"] = "observed" if executable else "unavailable"
        if executable is None and coverage["executable"] == "observed":
            coverage["executable"] = "unavailable"
        ppid = _get("parent", proc.ppid, coverage)
        uid = _get("uid", lambda: proc.uids().real, coverage)
        status = _get("status", proc.status, coverage, "unknown")
        resources = ResourceUsage()
        coverage["resources"] = "not_requested"
        if settings.resources:
            resources, coverage["resources"] = _resource_usage(
                proc, cpu_primed=resource_probe is not None
            )
        command_line = None
        coverage["command_line"] = "not_requested"
        if settings.command_line:
            raw = _get("command_line", proc.cmdline, coverage)
            if raw is not None:
                command_line, truncated = redact_argv(raw)
                if truncated:
                    coverage["command_line"] = "truncated"
    deleted = None
    if sys.platform == "linux":
        try:
            deleted = os.readlink(f"/proc/{pid}/exe").endswith(" (deleted)")
        except OSError:
            pass
    if executable and len(executable) > 8192:
        executable = executable[:8192]
        coverage["executable"] = "truncated"
    if executable and coverage["executable"] != "truncated":
        file_info, file_coverage = _file_info(executable, settings, file_cache)
    else:
        file_info, file_coverage = Executable(), {"file": "unavailable"}
    coverage.update(file_coverage)
    file_info = file_info.model_copy(update={"deleted": deleted})
    coverage["connections"] = "not_requested"
    freshness = "observed" if created is not None else "unverified"
    observations = _observations(executable, file_info)
    values = dict(pid=pid, created_at=created, name=name[:512], executable=executable, ppid=ppid, uid=uid,
                  status=status[:512], age_band=_age_band(created, now), command_line=command_line,
                  connections=[], resources=resources, file=file_info, coverage=coverage,
                  observations=observations, freshness=freshness)
    if len(name) > 512:
        coverage["name"] = "truncated"
    return Process.model_validate(values)


def _observations(path: str | None, info: Executable) -> list[str]:
    facts = []
    if path and any(path.startswith(prefix) for prefix in ("/tmp/", "/var/tmp/", "/private/tmp/")):
        facts.append("Executable path is in a temporary directory; legitimate development and installers also use these.")
    if info.deleted:
        facts.append("Linux reports a deleted executable image; updates and anonymous executable mappings can also cause this.")
    if info.mode is not None and info.mode & stat.S_IWOTH:
        facts.append("On-disk executable is world-writable; this is not proof of malicious execution.")
    if info.signature == "verification_failed":
        facts.append("On-disk code-signature verification failed; unsigned or ad-hoc development code may be legitimate.")
    return facts


def _live_parent(pid: int) -> tuple[Parent, int | None] | None:
    try:
        proc = psutil.Process(pid)
        oneshot = proc.oneshot() if hasattr(proc, "oneshot") else nullcontext()
        with oneshot:
            created = proc.create_time()
            name = _process_name_without_cmdline(proc, pid)
            executable = _process_executable_without_cmdline(proc, pid)
            ppid = proc.ppid()
        return (
            Parent(
                pid=pid,
                created_at=created,
                name=name[:512],
                executable=executable[:8192] if executable else None,
            ),
            ppid,
        )
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return None


def attach_ancestry(
    processes: list[Process],
    depth: int,
    *,
    resolve_missing: bool = False,
) -> list[Process]:
    by_pid = {p.pid: p for p in processes}
    result = []
    for process in processes:
        parents: list[Parent] = []
        next_pid = process.ppid
        current_created = process.created_at
        seen = {process.pid}
        state: Coverage = "not_requested" if depth == 0 else "observed"
        for _ in range(depth):
            if next_pid in (0, None):
                break
            if next_pid in seen or current_created is None:
                state = "partial"
                break
            parent_process = by_pid.get(next_pid)
            if parent_process is not None:
                if (
                    parent_process.created_at is None
                    or parent_process.created_at > current_created
                    or parent_process.freshness != "observed"
                ):
                    state = "partial"
                    break
                parent = Parent(
                    pid=parent_process.pid,
                    created_at=parent_process.created_at,
                    name=parent_process.name,
                    executable=parent_process.executable,
                )
                parent_ppid = parent_process.ppid
            elif resolve_missing:
                live = _live_parent(next_pid)
                if live is None:
                    state = "partial"
                    break
                parent, parent_ppid = live
                if parent.created_at > current_created:
                    state = "partial"
                    break
            else:
                state = "partial"
                break

            seen.add(parent.pid)
            parents.append(parent)
            current_created = parent.created_at
            next_pid = parent_ppid
        else:
            if depth and next_pid not in (0, None):
                state = "truncated"

        result.append(process.model_copy(update={
            "ancestors": parents,
            "coverage": {**process.coverage, "ancestry": state},
        }))
    return result


def _attach_network_one(
    process: Process,
    network: dict[int, list[Connection]],
    coverage: Coverage,
) -> Process:
    freshness = process.freshness
    entries = network.get(process.pid, [])
    state = coverage
    if freshness != "observed" or process.created_at is None:
        entries, state = [], "unavailable"
    else:
        try:
            # Fresh objects avoid psutil's cached executable/start-time attributes.
            current = psutil.Process(process.pid)
            oneshot = current.oneshot() if hasattr(current, "oneshot") else nullcontext()
            with oneshot:
                if current.create_time() != process.created_at:
                    freshness, entries, state = "reused", [], "unavailable"
                elif process.executable and current.exe() != process.executable:
                    freshness, entries, state = "changed", [], "unavailable"
        except psutil.NoSuchProcess:
            freshness, entries, state = "gone", [], "gone"
        except (psutil.AccessDenied, OSError):
            freshness, entries, state = "unverified", [], "unavailable"
    if len(entries) > 128:
        state = "truncated"
    return process.model_copy(update={
        "connections": entries[:128],
        "freshness": freshness,
        "coverage": {**process.coverage, "connections": state},
    })


def attach_network(
    processes: list[Process],
    network: dict[int, list[Connection]],
    coverage: Coverage,
) -> list[Process]:
    return [_attach_network_one(process, network, coverage) for process in processes]


def _attach_network_parallel(
    processes: list[Process],
    network: dict[int, list[Connection]],
    coverage: Coverage,
    executor: ThreadPoolExecutor,
) -> list[Process]:
    return list(
        executor.map(
            lambda process: _attach_network_one(process, network, coverage),
            processes,
        )
    )


def _collect_processes_parallel(
    selected: list[int],
    settings: CollectionSettings,
    now: float,
    resource_probes: dict[int, psutil.Process],
    executor: ThreadPoolExecutor,
    on_progress: Callable[[int, int], None] | None,
) -> list[Process]:
    # Expensive hash/signature inspection is deliberately split into the next phase.
    # This phase captures identity, argv, resources and cheap file metadata only.
    base_settings = settings.model_copy(update={"hashes": False, "signatures": False})
    if on_progress is not None:
        on_progress(0, len(selected))
    futures: dict[Future[Process], int] = {
        executor.submit(
            _process,
            pid,
            base_settings,
            now,
            None,
            resource_probes.get(pid),
        ): pid
        for pid in selected
    }
    by_pid: dict[int, Process] = {}
    for completed, future in enumerate(as_completed(futures), start=1):
        pid = futures[future]
        by_pid[pid] = future.result()
        if on_progress is not None and completed < len(selected):
            # The last unit is reserved until file/network/ancestry/child evidence
            # is attached, so the TTY never claims collection is complete early.
            on_progress(completed, len(selected))
    return [by_pid[pid] for pid in selected]


def _file_evidence_futures(
    processes: list[Process],
    settings: CollectionSettings,
    executor: ThreadPoolExecutor,
) -> dict[str, Future[tuple[Executable, dict[str, Coverage]]]]:
    if not (settings.hashes or settings.signatures):
        return {}
    paths = {
        process.executable
        for process in processes
        if process.executable
        and process.coverage.get("executable") != "truncated"
    }
    return {
        path: executor.submit(_file_info, path, settings, None)
        for path in sorted(paths)
    }


def _apply_file_evidence(
    processes: list[Process],
    evidence: dict[str, tuple[Executable, dict[str, Coverage]]],
) -> list[Process]:
    if not evidence:
        return processes
    result = []
    for process in processes:
        path = process.executable
        item = evidence.get(path) if path else None
        if item is None:
            result.append(process)
            continue
        file_info, file_coverage = item
        # Deleted-image state belongs to the process instance, while the remaining
        # file evidence is shared by every process referencing this inspected path.
        file_info = file_info.model_copy(update={"deleted": process.file.deleted})
        result.append(
            process.model_copy(update={
                "file": file_info,
                "coverage": {**process.coverage, **file_coverage},
                "observations": _observations(path, file_info),
            })
        )
    return result

def collect(
    settings: CollectionSettings,
    pids: list[int] | None = None,
    *,
    family_pid: int | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> Snapshot:
    if sys.platform not in {"linux", "darwin"}:
        raise CollectionError("live collection supports Linux and macOS; use a saved snapshot on other platforms")
    if pids is not None and family_pid is not None:
        raise CollectionError("PID selection and process-family selection are mutually exclusive")

    now = time.time()
    if family_pid is not None:
        candidates = _family_pids(family_pid)
    elif pids is not None:
        candidates = sorted(set(pids))
    else:
        candidates = sorted(set(psutil.pids()))

    omitted = max(0, len(candidates) - settings.max_processes)
    selected = candidates[:settings.max_processes]
    resource_probes = _prime_resource_probes(selected, settings)

    # Collection is blocking OS/file work, so a bounded thread pool is a better fit
    # than event-loop tasks. Phase ordering still preserves the identity/socket
    # safety contract: identities first, socket snapshot second, revalidation last.
    worker_count = min(settings.workers, max(1, len(selected)))
    with ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix="jevproc-collect",
    ) as executor:
        processes = _collect_processes_parallel(
            selected,
            settings,
            now,
            resource_probes,
            executor,
            on_progress,
        )

        # These operations are independent once the process identities are captured.
        network_future = executor.submit(_network, settings)
        child_future = (
            executor.submit(_child_index)
            if settings.child_limit > 0
            else None
        )
        file_futures = _file_evidence_futures(processes, settings, executor)

        file_evidence = {
            path: future.result()
            for path, future in file_futures.items()
        }
        processes = _apply_file_evidence(processes, file_evidence)

        # Capture sockets after the initial identity snapshot, then revalidate every
        # process in parallel so PID reuse/exec changes cannot inherit socket evidence.
        network, network_coverage = network_future.result()
        processes = _attach_network_parallel(
            processes,
            network,
            network_coverage,
            executor,
        )

        processes = attach_ancestry(
            processes,
            settings.ancestry_depth,
            resolve_missing=True,
        )

        if child_future is None:
            processes = _attach_children_from_index(
                processes,
                settings.child_limit,
                {},
                "not_requested",
            )
        else:
            by_parent, child_coverage = child_future.result()
            processes = _attach_children_from_index(
                processes,
                settings.child_limit,
                by_parent,
                child_coverage,
            )

    if on_progress is not None:
        on_progress(len(selected), len(selected))

    snapshot = Snapshot(
        captured_at=now,
        host=Host(
            platform=sys.platform,
            architecture=platform.machine()[:512],
            privileged=os.geteuid() == 0,
        ),
        processes=processes,
        omitted=omitted,
    )
    return sanitize_snapshot(snapshot, settings.command_line)

def load_snapshot(path: Path, include_command_line: bool = False) -> Snapshot:
    with path.open("rb") as handle:
        raw = handle.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise CollectionError("snapshot exceeds 16 MiB")
    snapshot = Snapshot.model_validate_json(raw)
    # Reapply privacy policy on import. A saved snapshot is untrusted external input.
    return sanitize_snapshot(snapshot, include_command_line)
