"""Read-only Linux/macOS snapshots. No target execution, memory reads or network probes."""

import os
import platform
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path

import psutil

from jevproc.core.config import CollectionSettings
from jevproc.core.evidence import CollectionError
from jevproc.core.evidence.files import _file_info, _observations
from jevproc.core.evidence.network import _attach_network_parallel, _network
from jevproc.core.evidence.process import _prime_resource_probes, _process
from jevproc.core.evidence.relationships import (
    _attach_children_from_index,
    _child_index,
    _family_pids,
    attach_ancestry,
)
from jevproc.core.models import (
    Coverage,
    Executable,
    Host,
    Process,
    Snapshot,
)
from jevproc.core.privacy import sanitize_snapshot


def _collect_processes_parallel(
    selected: list[int],
    settings: CollectionSettings,
    now: float,
    resource_probes: dict[int, psutil.Process],
    executor: ThreadPoolExecutor,
) -> list[Process]:
    # Expensive hash/signature inspection is deliberately split into the next phase.
    # This phase captures identity, argv, resources and cheap file metadata only.
    base_settings = settings.model_copy(update={"hashes": False, "signatures": False})
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
    for future in as_completed(futures):
        pid = futures[future]
        by_pid[pid] = future.result()
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
        if process.executable and process.coverage.get("executable") != "truncated"
    }
    return {path: executor.submit(_file_info, path, settings, None) for path in sorted(paths)}


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
            process.model_copy(
                update={
                    "file": file_info,
                    "coverage": {**process.coverage, **file_coverage},
                    "observations": _observations(path, file_info),
                }
            )
        )
    return result


def _candidate_process_ids(pids: list[int] | None, family_pid: int | None) -> list[int]:
    if family_pid is not None:
        return _family_pids(family_pid)
    if pids is not None:
        return sorted(set(pids))
    return sorted(set(psutil.pids()))


def _selected_process_ids(
    settings: CollectionSettings,
    pids: list[int] | None,
    family_pid: int | None,
) -> tuple[list[int], int]:
    candidates = _candidate_process_ids(pids, family_pid)
    return candidates[: settings.max_processes], max(0, len(candidates) - settings.max_processes)


def _attach_shared_evidence(
    processes: list[Process],
    settings: CollectionSettings,
    executor: ThreadPoolExecutor,
) -> list[Process]:
    network_future = executor.submit(_network, settings)
    child_future = executor.submit(_child_index) if settings.child_limit > 0 else None
    file_futures = _file_evidence_futures(processes, settings, executor)

    file_evidence = {path: future.result() for path, future in file_futures.items()}
    processes = _apply_file_evidence(processes, file_evidence)

    network, network_coverage = network_future.result()
    processes = _attach_network_parallel(processes, network, network_coverage, executor)
    processes = attach_ancestry(processes, settings.ancestry_depth, resolve_missing=True)

    if child_future is None:
        return _attach_children_from_index(processes, settings.child_limit, {}, "not_requested")
    by_parent, child_coverage = child_future.result()
    return _attach_children_from_index(processes, settings.child_limit, by_parent, child_coverage)


def _collect_selected_processes(
    selected: list[int],
    settings: CollectionSettings,
    now: float,
) -> list[Process]:
    resource_probes = _prime_resource_probes(selected, settings)
    worker_count = min(settings.workers, max(1, len(selected)))
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="jevproc-collect") as executor:
        processes = _collect_processes_parallel(selected, settings, now, resource_probes, executor)
        return _attach_shared_evidence(processes, settings, executor)


def _snapshot(now: float, processes: list[Process], omitted: int) -> Snapshot:
    return Snapshot(
        captured_at=now,
        host=Host(
            platform=sys.platform,
            architecture=platform.machine()[:512],
            privileged=os.geteuid() == 0,
        ),
        processes=processes,
        omitted=omitted,
    )


def collect(
    settings: CollectionSettings,
    pids: list[int] | None = None,
    *,
    family_pid: int | None = None,
) -> Snapshot:
    if sys.platform not in {"linux", "darwin"}:
        raise CollectionError("live collection supports Linux and macOS; use a saved snapshot on other platforms")
    if pids is not None and family_pid is not None:
        raise CollectionError("PID selection and process-family selection are mutually exclusive")

    now = time.time()
    selected, omitted = _selected_process_ids(settings, pids, family_pid)
    processes = _collect_selected_processes(selected, settings, now)
    return sanitize_snapshot(_snapshot(now, processes, omitted), settings.command_line)


def load_snapshot(path: Path, include_command_line: bool = False) -> Snapshot:
    with path.open("rb") as handle:
        raw = handle.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise CollectionError("snapshot exceeds 16 MiB")
    snapshot = Snapshot.model_validate_json(raw)
    # Reapply privacy policy on import. A saved snapshot is untrusted external input.
    return sanitize_snapshot(snapshot, include_command_line)
