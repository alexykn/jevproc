"""Numeric socket collection and process-instance revalidation."""

import os
import socket
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext

import psutil

from jevproc.core.config import CollectionSettings
from jevproc.core.models import (
    Connection,
    Coverage,
    Process,
)


def _endpoint(text: str) -> tuple[str, int]:
    """Parse one numeric lsof endpoint without DNS/service-name ambiguity."""
    value = text.strip()
    if " (" in value:
        value = value.rsplit(" (", 1)[0]
    if value.startswith("["):
        marker = value.rfind("]:")
        if marker >= 0:
            host, port = value[1:marker], value[marker + 2 :]
        else:
            return value[:512], 0
    else:
        host, separator, port = value.rpartition(":")
        if not separator:
            return value[:512], 0
    if not port.isdigit():
        return value[:512], 0
    return ("" if host == "*" else host[:512], int(port))


def _lsof_connection(
    pid: int | None,
    protocol: str,
    endpoint: str,
    status: str,
) -> Connection | None:
    if pid is None or protocol not in {"TCP", "UDP"} or not endpoint:
        return None
    local_text, arrow, remote_text = endpoint.partition("->")
    local_address, local_port = _endpoint(local_text)
    remote_address, remote_port = _endpoint(remote_text) if arrow else ("", 0)
    return Connection(
        protocol="tcp" if protocol == "TCP" else "udp",
        local_address=local_address,
        local_port=local_port,
        remote_address=remote_address,
        remote_port=remote_port,
        status=status[:512],
    )


def _deduplicated_connections(entries: list[Connection]) -> list[Connection]:
    unique = {
        (item.protocol, item.local_address, item.local_port, item.remote_address, item.remote_port, item.status): item
        for item in entries
    }
    return sorted(
        unique.values(),
        key=lambda item: (
            item.protocol,
            item.local_address,
            item.local_port,
            item.remote_address,
            item.remote_port,
            item.status,
        ),
    )


def _parse_lsof_network(output: str) -> dict[int, list[Connection]]:
    """Parse lsof field output; f records delimit sockets and p records delimit processes."""
    by_pid: dict[int, list[Connection]] = defaultdict(list)
    pid: int | None = None
    protocol = endpoint = status = ""

    def flush() -> None:
        nonlocal protocol, endpoint, status
        connection = _lsof_connection(pid, protocol, endpoint, status)
        if connection is not None and pid is not None:
            by_pid[pid].append(connection)
        protocol = endpoint = status = ""

    for line in filter(None, output.splitlines()):
        field, value = line[0], line[1:]
        if field in {"p", "f"}:
            flush()
        if field == "p":
            pid = int(value) if value.isdigit() else None
        elif field == "P":
            protocol = value.upper()
        elif field == "n":
            endpoint = value
        elif field == "T":
            status = value.removeprefix("ST=") if value.startswith("ST=") else status
    flush()
    return {owner: _deduplicated_connections(entries) for owner, entries in by_pid.items()}

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


def _socket_connection(item) -> Connection:
    return Connection(
        protocol="tcp" if item.type == socket.SOCK_STREAM else "udp",
        local_address=item.laddr.ip if item.laddr else "",
        local_port=item.laddr.port if item.laddr else 0,
        remote_address=item.raddr.ip if item.raddr else "",
        remote_port=item.raddr.port if item.raddr else 0,
        status=item.status,
    )


def _group_sockets(sockets) -> dict[int, list[Connection]]:
    by_pid: dict[int, list[Connection]] = defaultdict(list)
    for item in sockets:
        if item.pid is not None:
            by_pid[item.pid].append(_socket_connection(item))
    for entries in by_pid.values():
        entries.sort(key=lambda item: (item.protocol, item.local_address, item.local_port, item.remote_address, item.remote_port))
    return dict(by_pid)


def _psutil_network() -> tuple[dict[int, list[Connection]], Coverage]:
    try:
        sockets = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return _lsof_network() if sys.platform == "darwin" else ({}, "denied")
    except (OSError, NotImplementedError):
        return {}, "unavailable"
    incomplete = any((os.geteuid() != 0, any(item.pid is None for item in sockets)))
    return _group_sockets(sockets), "partial" if incomplete else "observed"


def _network(settings: CollectionSettings) -> tuple[dict[int, list[Connection]], Coverage]:
    return _psutil_network() if settings.connections else ({}, "not_requested")

def _executable_changed(current: psutil.Process, expected: str | None) -> bool:
    return bool(expected and current.exe() != expected)


def _revalidate_process(process: Process) -> tuple[str, Coverage]:
    try:
        current = psutil.Process(process.pid)
        oneshot = current.oneshot() if hasattr(current, "oneshot") else nullcontext()
        with oneshot:
            if current.create_time() != process.created_at:
                return "reused", "unavailable"
            if _executable_changed(current, process.executable):
                return "changed", "unavailable"
    except psutil.NoSuchProcess:
        return "gone", "gone"
    except (psutil.AccessDenied, OSError):
        return "unverified", "unavailable"
    return process.freshness, "observed"


def _network_state(
    process: Process,
    entries: list[Connection],
    coverage: Coverage,
) -> tuple[str, list[Connection], Coverage]:
    if process.freshness != "observed" or process.created_at is None:
        return process.freshness, [], "unavailable"
    freshness, verified = _revalidate_process(process)
    if verified != "observed":
        return freshness, [], verified
    return freshness, entries, "truncated" if len(entries) > 128 else coverage


def _attach_network_one(
    process: Process,
    network: dict[int, list[Connection]],
    coverage: Coverage,
) -> Process:
    entries = network.get(process.pid, [])
    freshness, entries, state = _network_state(process, entries, coverage)
    return process.model_copy(
        update={
            "connections": entries[:128],
            "freshness": freshness,
            "coverage": {**process.coverage, "connections": state},
        }
    )

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
