"""Per-process identity, invocation, and resource observations."""

import os
import sys
import time
from bisect import bisect_right
from contextlib import nullcontext, suppress
from pathlib import Path
from typing import Any, Callable, Protocol

import psutil

from jevproc.core.config import CollectionSettings
from jevproc.core.evidence.command import run_fixed
from jevproc.core.evidence.files import _file_info, _observations
from jevproc.core.models import (
    Coverage,
    Executable,
    Process,
    ResourceUsage,
)
from jevproc.core.privacy import redact_argv


def _get(field: str, action: Callable[[], Any], coverage: dict[str, Coverage], default: Any = None) -> Any:
    try:
        value = action()
    except psutil.AccessDenied:
        coverage[field] = "denied"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        coverage[field] = "gone"
    except (OSError, NotImplementedError):
        coverage[field] = "unavailable"
    else:
        coverage[field] = "observed"
        return value
    return default


class ResourceProcess(Protocol):
    def cpu_percent(self, interval: float | None = None) -> float: ...
    def memory_info(self) -> Any: ...
    def memory_percent(self) -> float: ...
    def num_threads(self) -> int: ...
    def num_fds(self) -> int: ...


def _resource_value(action: Callable[[], Any]) -> tuple[Any, Coverage]:
    try:
        return action(), "observed"
    except psutil.AccessDenied:
        return None, "denied"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None, "gone"
    except (OSError, NotImplementedError, AttributeError):
        return None, "unavailable"


def _resource_coverage(states: list[Coverage]) -> Coverage:
    observed = states.count("observed")
    outcomes: tuple[tuple[bool, Coverage], ...] = (
        (observed == len(states), "observed"),
        (bool(observed), "partial"),
        ("denied" in states, "denied"),
        ("gone" in states, "gone"),
    )
    return next((state for matches, state in outcomes if matches), "unavailable")


def _resource_usage(proc: ResourceProcess, cpu_primed: bool) -> tuple[ResourceUsage, Coverage]:
    cpu = _resource_value(lambda: proc.cpu_percent(interval=None)) if cpu_primed else (None, "unavailable")
    memory_info, memory_state = _resource_value(proc.memory_info)
    measurements = (
        ("cpu_percent", cpu),
        ("rss_bytes", (memory_info.rss if memory_info is not None else None, memory_state)),
        ("memory_percent", _resource_value(proc.memory_percent)),
        ("thread_count", _resource_value(proc.num_threads)),
        ("fd_count", _resource_value(proc.num_fds)),
    )
    values = {name: result[0] for name, result in measurements}
    states = [result[1] for _, result in measurements]
    return ResourceUsage.model_validate(values), _resource_coverage(states)

def _prime_resource_probe(pid: int) -> psutil.Process | None:
    try:
        proc = psutil.Process(pid)
        proc.cpu_percent(interval=None)
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return None
    else:
        return proc


def _prime_resource_probes(pids: list[int], settings: CollectionSettings) -> dict[int, psutil.Process]:
    if not settings.resources:
        return {}
    probes = {pid: probe for pid in pids if (probe := _prime_resource_probe(pid)) is not None}
    if probes:
        time.sleep(settings.resource_sample_seconds)
    return probes


def _comm_entry(line: str) -> tuple[int, str] | None:
    pid_text, separator, command = line.strip().partition(" ")
    command = command.strip()
    valid = all((bool(separator), pid_text.isdigit(), bool(command)))
    return (int(pid_text), command[:8192]) if valid else None


def _darwin_comm_table() -> dict[int, str]:
    result = run_fixed("/bin/ps", ("-axo", "pid=,comm="), timeout=5)
    if result is None or result.returncode != 0:
        return {}
    entries = filter(None, (_comm_entry(line) for line in result.stdout.splitlines()))
    return dict(entries)

def _darwin_comm(pid: int) -> str | None:
    result = run_fixed("/bin/ps", ("-p", str(pid), "-o", "comm="), timeout=2)
    if result is None or result.returncode != 0:
        return None
    return result.stdout.strip()[:8192] or None


def _linux_process_name(pid: int) -> str:
    with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as handle:
        return handle.read(513).strip()[:512] or "<unavailable>"


def _darwin_process_name(pid: int, command: str | None) -> str:
    value = command or _darwin_comm(pid)
    return os.path.basename(value)[:512] if value else "<unavailable>"


def _process_name_without_cmdline(
    proc: psutil.Process,
    pid: int,
    darwin_comm: str | None = None,
) -> str:
    resolvers = {
        "linux": lambda: _linux_process_name(pid),
        "darwin": lambda: _darwin_process_name(pid, darwin_comm),
    }
    action = resolvers.get(sys.platform, lambda: proc.name()[:512])
    try:
        return action()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return "<unavailable>"


def _linux_executable(pid: int) -> str | None:
    value = str(Path(f"/proc/{pid}/exe").readlink()).removesuffix(" (deleted)")
    return value[:8192] or None


def _darwin_executable(pid: int, command: str | None) -> str | None:
    value = command or _darwin_comm(pid)
    return value[:8192] if value else None


def _process_executable_without_cmdline(
    proc: psutil.Process,
    pid: int,
    darwin_comm: str | None = None,
) -> str | None:
    resolvers = {
        "linux": lambda: _linux_executable(pid),
        "darwin": lambda: _darwin_executable(pid, darwin_comm),
    }
    action = resolvers.get(sys.platform, lambda: (proc.exe() or None))
    try:
        value = action()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return None
    return value[:8192] if value else None

def _age_band(created: float | None, now: float) -> str:
    if created is None or created > now:
        return "unknown"
    labels = ("under_minute", "under_hour", "under_day", "older")
    return labels[bisect_right((60, 3600, 86400), now - created)]


def _live_process(pid: int, resource_probe: psutil.Process | None) -> psutil.Process | None:
    try:
        return resource_probe or psutil.Process(pid)
    except psutil.NoSuchProcess:
        return None


def _truncate_process_fields(fields: dict[str, Any], coverage: dict[str, Coverage]) -> str | None:
    executable = fields["executable"]
    if executable and len(executable) > 8192:
        executable = fields["executable"] = executable[:8192]
        coverage["executable"] = "truncated"
    if len(fields["name"]) > 512:
        coverage["name"] = "truncated"
    fields["name"] = fields["name"][:512]
    fields["status"] = fields["status"][:512]
    return executable


def _process_record(
    pid: int,
    now: float,
    fields: dict[str, Any],
    coverage: dict[str, Coverage],
    executable: str | None,
    file_info: Executable,
) -> Process:
    return Process.model_validate({
        **fields,
        "pid": pid,
        "age_band": _age_band(fields["created_at"], now),
        "freshness": "observed" if fields["created_at"] is not None else "unverified",
        "file": file_info,
        "coverage": coverage,
        "connections": [],
        "observations": _observations(executable, file_info),
    })


def _process(
    pid: int,
    settings: CollectionSettings,
    now: float,
    file_cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] | None = None,
    resource_probe: psutil.Process | None = None,
) -> Process:
    proc = _live_process(pid, resource_probe)
    if proc is None:
        return Process(pid=pid, freshness="gone", coverage={"identity": "gone"})
    fields, coverage = _process_metadata(proc, pid, settings, resource_probe is not None)
    executable = _truncate_process_fields(fields, coverage)
    file_info = _process_file(pid, executable, settings, coverage, file_cache)
    coverage["connections"] = "not_requested"
    return _process_record(pid, now, fields, coverage, executable, file_info)


def _psutil_identity(proc: psutil.Process, coverage: dict[str, Coverage]) -> tuple[str, str | None]:
    name = _get("name", proc.name, coverage, "<unavailable>")
    executable = _get("executable", proc.exe, coverage) or None
    if executable is None and coverage["executable"] == "observed":
        coverage["executable"] = "unavailable"
    return name, executable


def _direct_identity(proc: psutil.Process, pid: int, coverage: dict[str, Coverage]) -> tuple[str, str | None]:
    name = _process_name_without_cmdline(proc, pid)
    executable = _process_executable_without_cmdline(proc, pid)
    coverage["name"] = "observed" if name != "<unavailable>" else "unavailable"
    coverage["executable"] = "observed" if executable else "unavailable"
    return name, executable


def _identity_fields(
    proc: psutil.Process, pid: int, include_arguments: bool, coverage: dict[str, Coverage]
) -> tuple[str, str | None]:
    return _psutil_identity(proc, coverage) if include_arguments else _direct_identity(proc, pid, coverage)


def _command_arguments(proc: psutil.Process, enabled: bool, coverage: dict[str, Coverage]) -> list[str] | None:
    coverage["command_line"] = "not_requested"
    if not enabled:
        return None
    raw = _get("command_line", proc.cmdline, coverage)
    if raw is None:
        return None
    arguments, truncated = redact_argv(raw)
    if truncated:
        coverage["command_line"] = "truncated"
    return arguments


def _process_metadata(
    proc: psutil.Process, pid: int, settings: CollectionSettings, cpu_primed: bool
) -> tuple[dict[str, Any], dict[str, Coverage]]:
    coverage: dict[str, Coverage] = {}
    oneshot = proc.oneshot() if hasattr(proc, "oneshot") else nullcontext()
    with oneshot:
        created = _get("identity", proc.create_time, coverage)
        name, executable = _identity_fields(proc, pid, settings.command_line, coverage)
        fields = {
            "created_at": created,
            "name": name,
            "executable": executable,
            "ppid": _get("parent", proc.ppid, coverage),
            "uid": _get("uid", lambda: proc.uids().real, coverage),
            "status": _get("status", proc.status, coverage, "unknown"),
        }
        fields["resources"], coverage["resources"] = (
            _resource_usage(proc, cpu_primed) if settings.resources else (ResourceUsage(), "not_requested")
        )
        fields["command_line"] = _command_arguments(proc, settings.command_line, coverage)
    return fields, coverage


def _process_file(
    pid: int,
    executable: str | None,
    settings: CollectionSettings,
    coverage: dict[str, Coverage],
    file_cache: dict | None,
) -> Executable:
    deleted = None
    if sys.platform == "linux":
        with suppress(OSError):
            deleted = str(Path(f"/proc/{pid}/exe").readlink()).endswith(" (deleted)")
    file_coverage: dict[str, Coverage]
    if executable and coverage["executable"] != "truncated":
        file_info, file_coverage = _file_info(executable, settings, file_cache)
    else:
        file_info = Executable()
        file_coverage = {"file": "unavailable"}
    coverage.update(file_coverage)
    return file_info.model_copy(update={"deleted": deleted})
