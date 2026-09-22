"""Bounded ancestry, direct children, and family selection."""

import sys
from collections import defaultdict
from contextlib import nullcontext
from typing import Any

import psutil

from jevproc.core.evidence import CollectionError
from jevproc.core.evidence.process import (
    _darwin_comm_table,
    _process_executable_without_cmdline,
    _process_name_without_cmdline,
)
from jevproc.core.models import (
    Child,
    Coverage,
    Parent,
    Process,
)


def _child_index() -> tuple[dict[int, list[Child]], Coverage]:
    by_parent: dict[int, list[Child]] = defaultdict(list)
    incomplete = False
    commands = _darwin_comm_table() if sys.platform == "darwin" else {}
    try:
        for item in psutil.process_iter(["pid", "ppid", "create_time", "status"], ad_value=None):
            record = _child_record(item, item.info, commands)
            if record is None:
                incomplete = True
                continue
            ppid, child, complete = record
            incomplete = incomplete or not complete
            by_parent[ppid].append(child)
    except (OSError, NotImplementedError):
        return {}, "unavailable"
    for children in by_parent.values():
        children.sort(key=lambda child: (child.created_at or 0, child.pid))
    return dict(by_parent), "partial" if incomplete else "observed"


def _attach_children_from_index(
    processes: list[Process],
    limit: int,
    by_parent: dict[int, list[Child]],
    global_coverage: Coverage,
) -> list[Process]:
    if limit == 0:
        return [
            process.model_copy(
                update={
                    "children": [],
                    "child_count": 0,
                    "coverage": {**process.coverage, "children": "not_requested"},
                }
            )
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
        result.append(
            process.model_copy(
                update={
                    "children": entries[:limit],
                    "child_count": len(entries),
                    "coverage": {**process.coverage, "children": state},
                }
            )
        )
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


def attach_ancestry(processes: list[Process], depth: int, *, resolve_missing: bool = False) -> list[Process]:
    by_pid = {process.pid: process for process in processes}
    result = []
    for process in processes:
        parents, coverage = _ancestry(process, by_pid, depth, resolve_missing)
        result.append(
            process.model_copy(
                update={
                    "ancestors": parents,
                    "coverage": {**process.coverage, "ancestry": coverage},
                }
            )
        )
    return result


def _child_record(
    item: psutil.Process, info: dict[str, Any], darwin_commands: dict[int, str]
) -> tuple[int, Child, bool] | None:
    ppid, pid = info.get("ppid"), info.get("pid")
    if ppid is None or pid is None:
        return None
    pid = int(pid)
    command = darwin_commands.get(pid)
    name = _process_name_without_cmdline(item, pid, command)
    executable = _process_executable_without_cmdline(item, pid, command)
    created = info.get("create_time")
    child = Child(
        pid=pid, created_at=created, name=name, executable=executable, status=str(info.get("status") or "unknown")[:512]
    )
    complete = created is not None and executable is not None and name != "<unavailable>"
    return int(ppid), child, complete


def _resolve_parent(
    pid: int, created_before: float, by_pid: dict[int, Process], resolve_missing: bool
) -> tuple[Parent, int | None] | None:
    process = by_pid.get(pid)
    if process is None:
        link = _live_parent(pid) if resolve_missing else None
    elif process.created_at is None or process.freshness != "observed":
        return None
    else:
        link = (
            Parent(pid=process.pid, created_at=process.created_at, name=process.name, executable=process.executable),
            process.ppid,
        )
    if link is None or link[0].created_at > created_before:
        return None
    return link


def _ancestry(
    process: Process, by_pid: dict[int, Process], depth: int, resolve_missing: bool
) -> tuple[list[Parent], Coverage]:
    parents: list[Parent] = []
    seen = {process.pid}
    next_pid, created = process.ppid, process.created_at
    state: Coverage = "not_requested" if depth == 0 else "observed"
    for _ in range(depth):
        if next_pid in (0, None):
            return parents, state
        if next_pid in seen or created is None:
            return parents, "partial"
        link = _resolve_parent(next_pid, created, by_pid, resolve_missing)
        if link is None:
            return parents, "partial"
        parent, next_pid = link
        parents.append(parent)
        seen.add(parent.pid)
        created = parent.created_at
    if depth and next_pid not in (0, None):
        state = "truncated"
    return parents, state
