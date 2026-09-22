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
            by_pid[pid].append(
                Connection(
                    protocol="tcp" if protocol == "TCP" else "udp",
                    local_address=local_address,
                    local_port=local_port,
                    remote_address=remote_address,
                    remote_port=remote_port,
                    status=status[:512],
                )
            )
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
            (c.protocol, c.local_address, c.local_port, c.remote_address, c.remote_port, c.status): c for c in entries
        }
        result[owner] = sorted(
            unique.values(),
            key=lambda c: (
                c.protocol,
                c.local_address,
                c.local_port,
                c.remote_address,
                c.remote_port,
                c.status,
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
        by_pid[item.pid].append(
            Connection(
                protocol="tcp" if item.type == socket.SOCK_STREAM else "udp",
                local_address=item.laddr.ip if item.laddr else "",
                local_port=item.laddr.port if item.laddr else 0,
                remote_address=item.raddr.ip if item.raddr else "",
                remote_port=item.raddr.port if item.raddr else 0,
                status=item.status,
            )
        )
    for entries in by_pid.values():
        entries.sort(key=lambda c: (c.protocol, c.local_address, c.local_port, c.remote_address, c.remote_port))
    return dict(by_pid), "partial" if incomplete else "observed"


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
