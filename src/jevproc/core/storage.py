"""Private, TTL-bound answer cache. No raw process state or request bodies on disk."""

import hashlib
import os
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from jevproc.core.config import CacheSettings, Question
from jevproc.core.protocol import JevError, JevResponse, validate_response


class StorageError(RuntimeError):
    pass


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base and Path(base).is_absolute() else Path.home() / ".cache") / "jevproc"


@dataclass(frozen=True)
class _CreatedDirectory:
    path: Path
    device: int
    inode: int


def _missing_directory_chain(path: Path) -> list[Path]:
    missing: list[Path] = []
    current = path
    while True:
        try:
            current.lstat()
        except FileNotFoundError:
            missing.append(current)
            parent = current.parent
            if parent == current:
                break
            current = parent
            continue
        break
    return list(reversed(missing))


def _created_directory(path: Path) -> _CreatedDirectory:
    info = path.lstat()
    return _CreatedDirectory(path=path, device=info.st_dev, inode=info.st_ino)


def _rollback_directories(created: list[_CreatedDirectory]) -> None:
    for entry in reversed(created):
        try:
            info = entry.path.lstat()
        except FileNotFoundError:
            continue
        if (info.st_dev, info.st_ino) != (entry.device, entry.inode):
            continue
        try:
            entry.path.rmdir()
        except OSError:
            # Never remove a directory that acquired contents or otherwise changed.
            continue


def _create_directory_chain(path: Path) -> list[_CreatedDirectory]:
    created: list[_CreatedDirectory] = []
    try:
        for directory in _missing_directory_chain(path):
            mode = 0o700 if directory == path else 0o777
            try:
                directory.mkdir(mode=mode)
            except FileExistsError:
                continue
            created.append(_created_directory(directory))
    except BaseException:
        _rollback_directories(created)
        raise
    return created


def _validate_private_directory(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise StorageError("cache directory must be a private, owned directory (0700), not a symlink")


def _private_directory(path: Path) -> None:
    created = _create_directory_chain(path)
    try:
        _validate_private_directory(path)
    except BaseException:
        _rollback_directories(created)
        raise


def write_private(path: Path, data: bytes) -> None:
    """Exclusive creation: never follow links or overwrite an existing snapshot."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def request_key(origin: str, body: bytes) -> str:
    return hashlib.sha256(b"jevproc-cache-v1\0" + origin.encode() + b"\0" + body).hexdigest()


class AnswerCache:
    def __init__(self, directory: Path, settings: CacheSettings):
        self.db = _open_cache_database(_prepare_cache_file(directory))
        self.settings = settings

    def get(self, key: str, questions: dict[str, Question]) -> JevResponse | None:
        row = self.db.execute("SELECT expires, body FROM answers WHERE key=?", (key,)).fetchone()
        if row is None:
            return None
        if row[0] <= time.time() or not isinstance(row[1], bytes) or len(row[1]) > 2 * 1024 * 1024:
            self.delete(key)
            return None
        try:
            return validate_response(row[1], questions)
        except JevError:
            self.delete(key)
            return None

    def put(self, key: str, response: JevResponse) -> None:
        expires = time.time() + self.settings.ttl_seconds
        # A local cache is not a baseline/allowlist: identical evidence expires quickly.
        with self.db:
            self.db.execute("DELETE FROM answers WHERE expires<=?", (time.time(),))
            self.db.execute(
                "INSERT OR REPLACE INTO answers VALUES (?, ?, ?)", (key, expires, response.model_dump_json().encode())
            )
            self.db.execute(
                "DELETE FROM answers WHERE key IN (SELECT key FROM answers ORDER BY expires DESC LIMIT -1 OFFSET ?)",
                (self.settings.max_entries,),
            )

    def delete(self, key: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM answers WHERE key=?", (key,))

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.db.close()


def _open_cache_file(path: Path) -> tuple[int, bool]:
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        return os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600), True
    except FileExistsError:
        return os.open(path, flags), False


def _validate_cache_info(info: os.stat_result) -> None:
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
        raise StorageError("cache must be a private, owned regular file with one link")


def _rollback_created_cache(path: Path, info: os.stat_result | None) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if info is not None and (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
        return
    path.unlink()


@contextmanager
def _cache_descriptor(path: Path) -> Iterator[tuple[int, bool]]:
    fd, created = _open_cache_file(path)
    try:
        yield fd, created
    finally:
        os.close(fd)


def _validate_cache_file(path: Path) -> None:
    info: os.stat_result | None = None
    with _cache_descriptor(path) as (fd, created):
        try:
            info = os.fstat(fd)
            _validate_cache_info(info)
        except BaseException:
            if created:
                _rollback_created_cache(path, info)
            raise


def _prepare_cache_file(directory: Path) -> Path:
    """Ensure the private cache file exists and validates before SQLite opens it."""
    _private_directory(directory)
    path = directory / "answers.sqlite3"
    _validate_cache_file(path)
    return path

def _open_cache_database(path: Path) -> sqlite3.Connection:
    """Transfer ownership only after setup succeeds; close on every failure path."""
    with ExitStack() as cleanup:
        db = sqlite3.connect(path, timeout=5)
        cleanup.callback(db.close)
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute(
            "CREATE TABLE IF NOT EXISTS answers (key TEXT PRIMARY KEY, expires REAL NOT NULL, body BLOB NOT NULL)"
        )
        db.commit()
        cleanup.pop_all()
    return db
