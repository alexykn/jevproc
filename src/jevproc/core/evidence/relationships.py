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


def _child_records(commands: dict[int, str]) -> tuple[list[tuple[int, Child, bool]], Coverage]:
    records: list[tuple[int, Child, bool]] = []
    try:
        for item in psutil.process_iter(["pid", "ppid", "create_time", "status"], ad_value=None):
            record = _child_record(item, item.info, commands)
            if record is not None:
                records.append(record)
    except (OSError, NotImplementedError):
        return [], "unavailable"
    return records, "observed"


def _group_children(records: list[tuple[int, Child, bool]]) -> tuple[dict[int, list[Child]], bool]:
    by_parent: dict[int, list[Child]] = defaultdict(list)
    incomplete = False
    for ppid, child, complete in records:
        incomplete = incomplete or not complete
        by_parent[ppid].append(child)
    for children in by_parent.values():
        children.sort(key=lambda child: (child.created_at or 0, child.pid))
    return dict(by_parent), incomplete


def _child_index() -> tuple[dict[int, list[Child]], Coverage]:
    commands = _darwin_comm_table() if sys.platform == "darwin" else {}
    records, coverage = _child_records(commands)
    if coverage == "unavailable":
        return {}, coverage
    by_parent, incomplete = _group_children(records)
    return by_parent, "partial" if incomplete else "observed"

def _child_state(
    process: Process,
    entries: list[Child],
    limit: int,
    global_coverage: Coverage,
) -> tuple[list[Child], Coverage]:
    if process.freshness != "observed":
        return [], "unavailable"
    state = "truncated" if len(entries) > limit else global_coverage
    return entries[:limit], state


def _with_children(
    process: Process,
    entries: list[Child],
    limit: int,
    global_coverage: Coverage,
) -> Process:
    selected, state = _child_state(process, entries, limit, global_coverage)
    return process.model_copy(
        update={
            "children": selected,
            "child_count": len(entries),
            "coverage": {**process.coverage, "children": state},
        }
    )


def _without_children(process: Process) -> Process:
    return process.model_copy(
        update={
            "children": [],
            "child_count": 0,
            "coverage": {**process.coverage, "children": "not_requested"},
        }
    )


def _attach_children_from_index(
    processes: list[Process],
    limit: int,
    by_parent: dict[int, list[Child]],
    global_coverage: Coverage,
) -> list[Process]:
    if limit == 0:
        return list(map(_without_children, processes))
    return [
        _with_children(process, by_parent.get(process.pid, []), limit, global_coverage)
        for process in processes
    ]

def attach_children(processes: list[Process], limit: int) -> list[Process]:
    if limit == 0:
        return _attach_children_from_index(processes, limit, {}, "not_requested")
    by_parent, global_coverage = _child_index()
    return _attach_children_from_index(processes, limit, by_parent, global_coverage)


def _family_row(info: dict[str, Any]) -> tuple[int, int | None] | None:
    pid = info.get("pid")
    return None if pid is None else (int(pid), info.get("ppid"))


def _process_family_index() -> tuple[dict[int, list[int]], set[int]]:
    children: dict[int, list[int]] = defaultdict(list)
    seen_pids: set[int] = set()
    try:
        rows = filter(
            None,
            (_family_row(getattr(item, "info")) for item in psutil.process_iter(["pid", "ppid"], ad_value=None)),
        )
        for pid, ppid in rows:
            seen_pids.add(pid)
            if ppid is not None:
                children[int(ppid)].append(pid)
    except (OSError, NotImplementedError) as exc:
        raise CollectionError("could not enumerate process family") from exc
    return children, seen_pids

def _descendants(root_pid: int, children: dict[int, list[int]]) -> list[int]:
    ordered = [root_pid]
    seen = {root_pid}
    for parent in ordered:
        unseen = (child for child in sorted(children.get(parent, [])) if child not in seen)
        for child in unseen:
            seen.add(child)
            ordered.append(child)
    return ordered


def _family_pids(root_pid: int) -> list[int]:
    if not psutil.pid_exists(root_pid):
        raise CollectionError(f"process family root PID {root_pid} does not exist")
    children, seen_pids = _process_family_index()
    if root_pid not in seen_pids and not psutil.pid_exists(root_pid):
        raise CollectionError(f"process family root PID {root_pid} exited")
    return _descendants(root_pid, children)

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


def _child_ids(info: dict[str, Any]) -> tuple[int, int] | None:
    ppid, pid = info.get("ppid"), info.get("pid")
    return None if ppid is None or pid is None else (int(ppid), int(pid))


def _child_record(
    item: psutil.Process, info: dict[str, Any], darwin_commands: dict[int, str]
) -> tuple[int, Child, bool] | None:
    ids = _child_ids(info)
    if ids is None:
        return None
    ppid, pid = ids
    command = darwin_commands.get(pid)
    name = _process_name_without_cmdline(item, pid, command)
    executable = _process_executable_without_cmdline(item, pid, command)
    created = info.get("create_time")
    child = Child(
        pid=pid,
        created_at=created,
        name=name,
        executable=executable,
        status=str(info.get("status") or "unknown")[:512],
    )
    complete = all((created is not None, executable is not None, name != "<unavailable>"))
    return ppid, child, complete

def _selected_parent(process: Process) -> tuple[Parent, int | None] | None:
    if process.created_at is None or process.freshness != "observed":
        return None
    return (
        Parent(pid=process.pid, created_at=process.created_at, name=process.name, executable=process.executable),
        process.ppid,
    )


def _parent_link(
    pid: int,
    by_pid: dict[int, Process],
    resolve_missing: bool,
) -> tuple[Parent, int | None] | None:
    process = by_pid.get(pid)
    if process is not None:
        return _selected_parent(process)
    return _live_parent(pid) if resolve_missing else None


def _resolve_parent(
    pid: int, created_before: float, by_pid: dict[int, Process], resolve_missing: bool
) -> tuple[Parent, int | None] | None:
    link = _parent_link(pid, by_pid, resolve_missing)
    return link if link is not None and link[0].created_at <= created_before else None

def _next_ancestor(
    next_pid: int | None,
    created: float | None,
    seen: set[int],
    by_pid: dict[int, Process],
    resolve_missing: bool,
) -> tuple[Parent, int | None] | None:
    if next_pid in (0, None) or next_pid in seen or created is None:
        return None
    return _resolve_parent(next_pid, created, by_pid, resolve_missing)


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
        link = _next_ancestor(next_pid, created, seen, by_pid, resolve_missing)
        if link is None:
            return parents, "partial"
        parent, next_pid = link
        parents.append(parent)
        seen.add(parent.pid)
        created = parent.created_at

    truncated = depth > 0 and next_pid not in (0, None)
    return parents, "truncated" if truncated else state

