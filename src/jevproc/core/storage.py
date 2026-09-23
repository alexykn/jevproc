"""Private, TTL-bound answer cache. No raw process state or request bodies on disk."""

import hashlib
import os
import sqlite3
import stat
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Self

from jevproc.core.config import CacheSettings, Question
from jevproc.core.protocol import JevError, JevResponse, validate_response


class StorageError(RuntimeError):
    pass


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base and Path(base).is_absolute() else Path.home() / ".cache") / "jevproc"


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise StorageError("cache directory must be a private, owned directory (0700), not a symlink")


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


def _prepare_cache_file(directory: Path) -> Path:
    """Create-or-open the cache file; rollback only a file created by this call."""
    _private_directory(directory)
    path = directory / "answers.sqlite3"
    fd, created = _open_cache_file(path)
    info: os.stat_result | None = None
    try:
        info = os.fstat(fd)
        _validate_cache_info(info)
    except BaseException:
        if created:
            _rollback_created_cache(path, info)
        raise
    finally:
        os.close(fd)
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
