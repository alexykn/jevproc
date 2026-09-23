"""Numeric socket collection and process-instance revalidation."""

import os
import socket
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from dataclasses import dataclass, field

import psutil

from jevproc.core.config import CollectionSettings
from jevproc.core.evidence.access import observed
from jevproc.core.models import (
    Connection,
    Coverage,
    Process,
)


def _strip_endpoint_annotation(value: str) -> str:
    return value.rsplit(" (", 1)[0] if " (" in value else value


def _split_bracketed_endpoint(value: str) -> tuple[str, str] | None:
    marker = value.rfind("]:")
    return (value[1:marker], value[marker + 2 :]) if marker >= 0 else None


def _split_plain_endpoint(value: str) -> tuple[str, str] | None:
    host, separator, port = value.rpartition(":")
    return (host, port) if separator else None


def _split_endpoint(value: str) -> tuple[str, str] | None:
    return _split_bracketed_endpoint(value) if value.startswith("[") else _split_plain_endpoint(value)


def _endpoint(text: str) -> tuple[str, int]:
    """Parse one numeric lsof endpoint without DNS/service-name ambiguity."""
    value = _strip_endpoint_annotation(text.strip())
    parts = _split_endpoint(value)
    if parts is None:
        return value[:512], 0
    host, port = parts
    if not port.isdigit():
        return value[:512], 0
    return ("" if host == "*" else host[:512], int(port))


def _lsof_connection(
    pid: int | None,
    protocol: str,
    endpoint: str,
    status: str,
) -> Connection | None:
    ready = all((pid is not None, protocol in {"TCP", "UDP"}, bool(endpoint)))
    if not ready:
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


@dataclass
class _LsofParser:
    by_pid: dict[int, list[Connection]] = field(default_factory=dict)
    pid: int | None = None
    protocol: str = ""
    endpoint: str = ""
    status: str = ""

    def _reset_socket(self) -> None:
        self.protocol = self.endpoint = self.status = ""

    def _flush(self) -> None:
        connection = _lsof_connection(self.pid, self.protocol, self.endpoint, self.status)
        if connection is not None and self.pid is not None:
            self.by_pid.setdefault(self.pid, []).append(connection)
        self._reset_socket()

    def _process(self, value: str) -> None:
        self._flush()
        self.pid = int(value) if value.isdigit() else None

    def _file(self, _value: str) -> None:
        self._flush()

    def _protocol(self, value: str) -> None:
        self.protocol = value.upper()

    def _endpoint(self, value: str) -> None:
        self.endpoint = value

    def _status(self, value: str) -> None:
        if value.startswith("ST="):
            self.status = value.removeprefix("ST=")

    def feed(self, line: str) -> None:
        handlers = {
            "p": self._process,
            "f": self._file,
            "P": self._protocol,
            "n": self._endpoint,
            "T": self._status,
        }
        handler = handlers.get(line[0])
        if handler is not None:
            handler(line[1:])

    def result(self) -> dict[int, list[Connection]]:
        self._flush()
        return {owner: _deduplicated_connections(entries) for owner, entries in self.by_pid.items()}


def _parse_lsof_network(output: str) -> dict[int, list[Connection]]:
    """Parse lsof field output; f records delimit sockets and p records delimit processes."""
    parser = _LsofParser()
    for line in filter(None, output.splitlines()):
        parser.feed(line)
    return parser.result()


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


def _socket_address(address) -> tuple[str, int]:
    return (address.ip, address.port) if address else ("", 0)


def _socket_connection(item) -> Connection:
    local_address, local_port = _socket_address(item.laddr)
    remote_address, remote_port = _socket_address(item.raddr)
    return Connection(
        protocol="tcp" if item.type == socket.SOCK_STREAM else "udp",
        local_address=local_address,
        local_port=local_port,
        remote_address=remote_address,
        remote_port=remote_port,
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
    sockets, state = observed(lambda: psutil.net_connections(kind="inet"), [])
    if state == "denied" and sys.platform == "darwin":
        return _lsof_network()
    if state != "observed":
        return {}, "denied" if state == "denied" else "unavailable"
    incomplete = any((os.geteuid() != 0, any(item.pid is None for item in sockets)))
    return _group_sockets(sockets), "partial" if incomplete else "observed"


def _network(settings: CollectionSettings) -> tuple[dict[int, list[Connection]], Coverage]:
    return _psutil_network() if settings.connections else ({}, "not_requested")

def _executable_changed(current: psutil.Process, expected: str | None) -> bool:
    return bool(expected and current.exe() != expected)


def _live_process(pid: int) -> tuple[psutil.Process | None, Coverage]:
    return observed(lambda: psutil.Process(pid))


def _live_created_at(current: psutil.Process) -> tuple[float | None, Coverage]:
    return observed(current.create_time)


def _live_executable(current: psutil.Process, expected: str | None) -> tuple[str | None, Coverage]:
    return observed(current.exe) if expected else (None, "observed")


def _unverified_state(state: Coverage) -> tuple[str, Coverage]:
    return ("gone", "gone") if state == "gone" else ("unverified", "unavailable")


def _revalidate_process(process: Process) -> tuple[str, Coverage]:
    current, state = _live_process(process.pid)
    if state != "observed" or current is None:
        return _unverified_state(state)

    created, state = _live_created_at(current)
    if state != "observed":
        return _unverified_state(state)
    if created != process.created_at:
        return "reused", "unavailable"

    executable, state = _live_executable(current, process.executable)
    if state != "observed":
        return _unverified_state(state)
    if process.executable and executable != process.executable:
        return "changed", "unavailable"
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
