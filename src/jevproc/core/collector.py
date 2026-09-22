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
from pathlib import Path
from typing import Any, Callable

import psutil

from jevproc.core.config import CollectionSettings
from jevproc.core.models import Connection, Coverage, Executable, Host, Parent, Process, Snapshot
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


def _signature(path: str) -> tuple[dict[str, Any], Coverage]:
    if sys.platform != "darwin":
        return {"signature": "unavailable"}, "unavailable"
    try:
        verify = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--strict", "--", path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"signature": "unavailable"}, "unavailable"

    if verify.returncode != 0:
        return {"signature": "verification_failed"}, "observed"

    values: dict[str, Any] = {"signature": "valid"}
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
    # Verification proves only that the on-disk signature is structurally valid.
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
) -> Process:
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return Process(pid=pid, freshness="gone", coverage={"identity": "gone"})
    coverage: dict[str, Coverage] = {}
    created = _get("identity", proc.create_time, coverage)
    name = _get("name", proc.name, coverage, "<unavailable>")
    executable = _get("executable", proc.exe, coverage) or None
    if executable is None and coverage["executable"] == "observed":
        coverage["executable"] = "unavailable"
    ppid = _get("parent", proc.ppid, coverage)
    uid = _get("uid", lambda: proc.uids().real, coverage)
    status = _get("status", proc.status, coverage, "unknown")
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
                  connections=[], file=file_info, coverage=coverage,
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


def attach_ancestry(processes: list[Process], depth: int) -> list[Process]:
    by_pid = {p.pid: p for p in processes}
    result = []
    for process in processes:
        parents: list[Parent] = []
        current = process
        seen = {process.pid}
        state: Coverage = "not_requested" if depth == 0 else "observed"
        for _ in range(depth):
            if current.ppid == 0:
                break
            parent = by_pid.get(current.ppid) if current.ppid is not None else None
            if (parent is None or parent.pid in seen or parent.created_at is None or
                current.created_at is None or parent.created_at > current.created_at or
                parent.freshness != "observed"):
                state = "partial"
                break
            seen.add(parent.pid)
            parents.append(Parent(pid=parent.pid, created_at=parent.created_at, name=parent.name,
                                  executable=parent.executable))
            current = parent
        else:
            if depth and current.ppid not in (0, None):
                state = "truncated"
        result.append(process.model_copy(update={
            "ancestors": parents, "coverage": {**process.coverage, "ancestry": state}
        }))
    return result


def attach_network(processes: list[Process], network: dict[int, list[Connection]], coverage: Coverage) -> list[Process]:
    results = []
    for process in processes:
        freshness = process.freshness
        entries = network.get(process.pid, [])
        state = coverage
        if freshness != "observed" or process.created_at is None:
            entries, state = [], "unavailable"
        else:
            try:
                # Fresh objects avoid psutil's cached executable/start-time attributes.
                current = psutil.Process(process.pid)
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
        results.append(process.model_copy(update={
            "connections": entries[:128], "freshness": freshness,
            "coverage": {**process.coverage, "connections": state},
        }))
    return results


def collect(settings: CollectionSettings, pids: list[int] | None = None) -> Snapshot:
    if sys.platform not in {"linux", "darwin"}:
        raise CollectionError("live collection supports Linux and macOS; use a saved snapshot on other platforms")
    now = time.time()
    selected = sorted(set(pids if pids is not None else psutil.pids()))
    omitted = max(0, len(selected) - settings.max_processes)
    selected = selected[:settings.max_processes]
    file_cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] = {}
    processes = [_process(pid, settings, now, file_cache) for pid in selected]
    # Capture sockets AFTER process identities and revalidate those identities afterwards.
    # Otherwise a reused PID could inherit the previous process's network evidence.
    network, coverage = _network(settings)
    processes = attach_network(processes, network, coverage)
    processes = attach_ancestry(processes, settings.ancestry_depth)
    snapshot = Snapshot(captured_at=now, host=Host(platform=sys.platform,
                        architecture=platform.machine()[:512], privileged=os.geteuid() == 0),
                        processes=processes, omitted=omitted)
    return sanitize_snapshot(snapshot, settings.command_line)


def load_snapshot(path: Path, include_command_line: bool = False) -> Snapshot:
    with path.open("rb") as handle:
        raw = handle.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise CollectionError("snapshot exceeds 16 MiB")
    snapshot = Snapshot.model_validate_json(raw)
    # Reapply privacy policy on import. A saved snapshot is untrusted external input.
    return sanitize_snapshot(snapshot, include_command_line)
