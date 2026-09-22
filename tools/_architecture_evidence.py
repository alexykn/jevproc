"""Split OS evidence ownership while retaining the bounded parallel collector."""
import ast
from collections import defaultdict

from _architecture_tools import ROOT, add_imports, append, extract, imports, read, replace, write

GROUPS = {
    'files': ['_hash_file', '_classify_codesign_failure', '_signature', '_file_info', '_observations'],
    'process': ['_get', '_resource_value', '_resource_usage', '_prime_resource_probes', '_darwin_comm_table',
                '_darwin_comm', '_process_name_without_cmdline', '_process_executable_without_cmdline', '_age_band', '_process'],
    'network': ['_endpoint', '_parse_lsof_network', '_lsof_network', '_network', '_attach_network_one',
                'attach_network', '_attach_network_parallel'],
    'relationships': ['_child_index', '_attach_children_from_index', 'attach_children', '_family_pids',
                      '_live_parent', 'attach_ancestry'],
}
OWNERS = {name: group for group, names in GROUPS.items() for name in names}


def apply():
    collector = 'src/jevproc/core/collector.py'
    original = read(collector)
    write('src/jevproc/core/evidence/__init__.py', '''
"""Read-only OS evidence backends. No inference, rendering, or mutable target state."""

class CollectionError(RuntimeError):
    pass
''')
    descriptions = {
        'files': 'On-disk metadata, bounded hashing, and macOS signature diagnostics.',
        'process': 'Per-process identity, invocation, and resource observations.',
        'network': 'Numeric socket collection and process-instance revalidation.',
        'relationships': 'Bounded ancestry, direct children, and family selection.',
    }
    extras = {
        'files': '',
        'process': 'from jevproc.core.evidence.files import _file_info, _observations',
        'network': '',
        'relationships': ('from jevproc.core.evidence import CollectionError\n'
                          'from jevproc.core.evidence.process import _darwin_comm_table, _process_name_without_cmdline, _process_executable_without_cmdline'),
    }
    for group, names in GROUPS.items():
        code = '\n\n\n'.join(extract(original, name) for name in names)
        write(f'src/jevproc/core/evidence/{group}.py',
              f'"""{descriptions[group]}"""\n\n' + imports(original) + '\n' + extras[group] + '\n\n' + code)
    # Keep public collection orchestration where callers expect it. Private backends
    # have one actual home instead of compatibility wrappers with split patch points.
    removed = set(OWNERS) | {'CollectionError'}
    lines = original.splitlines(keepends=True)
    for node in reversed(ast.parse(original).body):
        if getattr(node, 'name', None) in removed:
            del lines[node.lineno - 1:node.end_lineno]
    write(collector, ''.join(lines))
    add_imports(collector, '''
from jevproc.core.evidence import CollectionError
from jevproc.core.evidence.files import _file_info, _observations
from jevproc.core.evidence.process import _process, _prime_resource_probes
from jevproc.core.evidence.network import _network, _attach_network_parallel
from jevproc.core.evidence.relationships import _family_pids, _child_index, _attach_children_from_index, attach_ancestry
''')

    files = 'src/jevproc/core/evidence/files.py'
    append(files, '''
def _file_coverage(settings: CollectionSettings) -> dict[str, Coverage]:
    return {
        "file": "unavailable",
        "hash": "unavailable" if settings.hashes else "not_requested",
        "signature": "unavailable" if settings.signatures else "not_requested",
    }


def _stat_executable(path: str) -> tuple[Executable, Coverage, os.stat_result | None]:
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return Executable(exists=False), "observed", None
    except PermissionError:
        return Executable(), "denied", None
    except OSError:
        return Executable(), "unavailable", None
    return Executable(exists=True, size=info.st_size, mode=stat.S_IMODE(info.st_mode),
                      owner_uid=info.st_uid, modified_ns=info.st_mtime_ns), "observed", info


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _file_unchanged(path: str, before: os.stat_result) -> bool:
    try:
        return _file_identity(before) == _file_identity(os.stat(path))
    except OSError:
        return False


def _inspect_content(path: str, metadata: Executable, settings: CollectionSettings,
                     coverage: dict[str, Coverage]) -> Executable:
    values = metadata.model_dump()
    if settings.hashes:
        values["sha256"], coverage["hash"] = _hash_file(path, settings.max_hash_bytes)
    if settings.signatures:
        signature, coverage["signature"] = _signature(path)
        values.update(signature)
    return Executable.model_validate(values)
''')
    replace(files, '_file_info', '''
def _file_info(path: str | None, settings: CollectionSettings,
               cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] | None = None
               ) -> tuple[Executable, dict[str, Coverage]]:
    coverage = _file_coverage(settings)
    if not path or not os.path.isabs(path) or "\\x00" in path:
        return Executable(), coverage
    metadata, coverage["file"], info = _stat_executable(path)
    if info is None:
        return metadata, coverage
    key = (path, *_file_identity(info), settings.hashes, settings.signatures, settings.max_hash_bytes)
    if cache is not None and key in cache:
        cached, cached_coverage = cache[key]
        return cached, dict(cached_coverage)
    inspected = _inspect_content(path, metadata, settings, coverage) if stat.S_ISREG(info.st_mode) else metadata
    if (settings.hashes or settings.signatures) and not _file_unchanged(path, info):
        # Never combine a file's old metadata with a replacement's inspection.
        return Executable(), {**_file_coverage(settings), "file": "partial"}
    if cache is not None:
        cache[key] = inspected, dict(coverage)
    return inspected, coverage
''')

    process = 'src/jevproc/core/evidence/process.py'
    append(process, '''
def _identity_fields(proc: psutil.Process, pid: int, include_arguments: bool,
                     coverage: dict[str, Coverage]) -> tuple[str, str | None]:
    if include_arguments:
        name = _get("name", proc.name, coverage, "<unavailable>")
        executable = _get("executable", proc.exe, coverage) or None
        if executable is None and coverage["executable"] == "observed":
            coverage["executable"] = "unavailable"
        return name, executable
    name = _process_name_without_cmdline(proc, pid)
    executable = _process_executable_without_cmdline(proc, pid)
    coverage["name"] = "observed" if name != "<unavailable>" else "unavailable"
    coverage["executable"] = "observed" if executable else "unavailable"
    return name, executable


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


def _process_metadata(proc: psutil.Process, pid: int, settings: CollectionSettings,
                      cpu_primed: bool) -> tuple[dict[str, Any], dict[str, Coverage]]:
    coverage: dict[str, Coverage] = {}
    oneshot = proc.oneshot() if hasattr(proc, "oneshot") else nullcontext()
    with oneshot:
        created = _get("identity", proc.create_time, coverage)
        name, executable = _identity_fields(proc, pid, settings.command_line, coverage)
        fields = {
            "created_at": created, "name": name, "executable": executable,
            "ppid": _get("parent", proc.ppid, coverage),
            "uid": _get("uid", lambda: proc.uids().real, coverage),
            "status": _get("status", proc.status, coverage, "unknown"),
        }
        fields["resources"], coverage["resources"] = (
            _resource_usage(proc, cpu_primed) if settings.resources else (ResourceUsage(), "not_requested")
        )
        fields["command_line"] = _command_arguments(proc, settings.command_line, coverage)
    return fields, coverage


def _process_file(pid: int, executable: str | None, settings: CollectionSettings,
                  coverage: dict[str, Coverage], file_cache: dict | None) -> Executable:
    deleted = None
    if sys.platform == "linux":
        try:
            deleted = os.readlink(f"/proc/{pid}/exe").endswith(" (deleted)")
        except OSError:
            pass
    if executable and coverage["executable"] != "truncated":
        file_info, file_coverage = _file_info(executable, settings, file_cache)
    else:
        file_info, file_coverage = Executable(), {"file": "unavailable"}
    coverage.update(file_coverage)
    return file_info.model_copy(update={"deleted": deleted})
''')
    replace(process, '_process', '''
def _process(pid: int, settings: CollectionSettings, now: float,
             file_cache: dict[tuple, tuple[Executable, dict[str, Coverage]]] | None = None,
             resource_probe: psutil.Process | None = None) -> Process:
    try:
        proc = resource_probe or psutil.Process(pid)
    except psutil.NoSuchProcess:
        return Process(pid=pid, freshness="gone", coverage={"identity": "gone"})
    fields, coverage = _process_metadata(proc, pid, settings, resource_probe is not None)
    executable = fields["executable"]
    if executable and len(executable) > 8192:
        executable = fields["executable"] = executable[:8192]
        coverage["executable"] = "truncated"
    file_info = _process_file(pid, executable, settings, coverage, file_cache)
    if len(fields["name"]) > 512:
        coverage["name"] = "truncated"
    fields["name"] = fields["name"][:512]
    fields["status"] = fields["status"][:512]
    coverage["connections"] = "not_requested"
    return Process.model_validate({
        **fields, "pid": pid, "age_band": _age_band(fields["created_at"], now),
        "freshness": "observed" if fields["created_at"] is not None else "unverified",
        "file": file_info, "coverage": coverage, "connections": [],
        "observations": _observations(executable, file_info),
    })
''')

    relationships = 'src/jevproc/core/evidence/relationships.py'
    append(relationships, '''
def _child_record(item: psutil.Process, darwin_commands: dict[int, str]) -> tuple[int, Child, bool] | None:
    info = item.info
    ppid, pid = info.get("ppid"), info.get("pid")
    if ppid is None or pid is None:
        return None
    pid = int(pid)
    command = darwin_commands.get(pid)
    name = _process_name_without_cmdline(item, pid, command)
    executable = _process_executable_without_cmdline(item, pid, command)
    created = info.get("create_time")
    child = Child(pid=pid, created_at=created, name=name, executable=executable,
                  status=str(info.get("status") or "unknown")[:512])
    complete = created is not None and executable is not None and name != "<unavailable>"
    return int(ppid), child, complete


def _resolve_parent(pid: int, created_before: float, by_pid: dict[int, Process],
                    resolve_missing: bool) -> tuple[Parent, int | None] | None:
    process = by_pid.get(pid)
    if process is None:
        link = _live_parent(pid) if resolve_missing else None
    elif process.created_at is None or process.freshness != "observed":
        return None
    else:
        link = Parent(pid=process.pid, created_at=process.created_at, name=process.name,
                      executable=process.executable), process.ppid
    if link is None or link[0].created_at > created_before:
        return None
    return link


def _ancestry(process: Process, by_pid: dict[int, Process], depth: int,
              resolve_missing: bool) -> tuple[list[Parent], Coverage]:
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
''')
    replace(relationships, '_child_index', '''
def _child_index() -> tuple[dict[int, list[Child]], Coverage]:
    by_parent: dict[int, list[Child]] = defaultdict(list)
    incomplete = False
    commands = _darwin_comm_table() if sys.platform == "darwin" else {}
    try:
        for item in psutil.process_iter(["pid", "ppid", "create_time", "status"], ad_value=None):
            record = _child_record(item, commands)
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
''')
    replace(relationships, 'attach_ancestry', '''
def attach_ancestry(processes: list[Process], depth: int, *, resolve_missing: bool = False) -> list[Process]:
    by_pid = {process.pid: process for process in processes}
    result = []
    for process in processes:
        parents, coverage = _ancestry(process, by_pid, depth, resolve_missing)
        result.append(process.model_copy(update={
            "ancestors": parents, "coverage": {**process.coverage, "ancestry": coverage},
        }))
    return result
''')
    _redirect_private_tests()


def _redirect_private_tests():
    # Tests patch the backend that now owns an operation, not a compatibility alias.
    test_backend = {
        'test_codesign_never_runs_target_or_shell_and_parses_identity': 'files',
        'test_legacy_codesign_keeps_signer_metadata': 'files',
        'test_unsigned_codesign_skips_display': 'files',
        'test_failed_codesign_can_preserve_display_identity': 'files',
        'test_replaced_file_evidence_is_not_combined': 'files',
        'test_file_inspection_cache_deduplicates_hash_and_signature': 'files',
        'test_macos_network_falls_back_to_lsof': 'network',
        'test_children_are_bounded_and_total_count_is_preserved': 'relationships',
        'test_family_selection_walks_descendants_only': 'relationships',
        'test_live_missing_parent_can_be_resolved_for_single_pid': 'relationships',
    }
    for path in (ROOT / 'tests').glob('test_*.py'):
        source = path.read_text()
        lines = source.splitlines(keepends=True)
        edits = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.module == 'jevproc.core.collector':
                groups = defaultdict(list)
                for alias in node.names:
                    owner = OWNERS.get(alias.name)
                    module = f'jevproc.core.evidence.{owner}' if owner else node.module
                    groups[module].append(alias.name + (f' as {alias.asname}' if alias.asname else ''))
                replacement = '\n'.join(' ' * node.col_offset + f'from {module} import ' + ', '.join(names)
                                         for module, names in groups.items()) + '\n'
                edits.append((node.lineno - 1, node.end_lineno, replacement))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in test_backend:
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Import):
                        for alias in inner.names:
                            if alias.name == 'jevproc.core.collector':
                                module = f'jevproc.core.evidence.{test_backend[node.name]}'
                                replacement = ' ' * inner.col_offset + f'import {module} as {alias.asname}\n'
                                edits.append((inner.lineno - 1, inner.end_lineno, replacement))
        if edits:
            for start, end, replacement in sorted(edits, reverse=True):
                lines[start:end] = [replacement]
            write(str(path.relative_to(ROOT)), ''.join(lines))
