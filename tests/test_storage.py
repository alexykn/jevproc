import time

import pytest

from jevproc.core.config import CacheSettings, NoulQuestion
from jevproc.core.protocol import encode, validate_response
from jevproc.core.storage import AnswerCache, StorageError, request_key, write_private

Q = {"q": NoulQuestion(type="noul", instructions="Evidence?")}
RESPONSE = validate_response(encode({"model": "jev-1.13.0", "answers": {"q": {"type": "noul", "noul": 0.2}}}), Q)


def test_private_cache_roundtrip_and_no_process_state(tmp_path):
    directory = tmp_path / "private"
    key = request_key("https://api.typesafe.ai", b"PRIVATE-PROCESS-COMMAND")
    with AnswerCache(directory, CacheSettings()) as cache:
        cache.put(key, RESPONSE)
        assert cache.get(key, Q) == RESPONSE
        assert (directory.stat().st_mode & 0o777) == 0o700
        assert ((directory / "answers.sqlite3").stat().st_mode & 0o777) == 0o600
        assert b"PRIVATE-PROCESS-COMMAND" not in (directory / "answers.sqlite3").read_bytes()


def test_cache_key_separates_endpoint_state_and_questions():
    assert request_key("a", b"x") != request_key("b", b"x")
    assert request_key("a", b"x") != request_key("a", b"y")


def test_expired_and_corrupt_answers_are_refetched(tmp_path):
    with AnswerCache(tmp_path / "cache", CacheSettings()) as cache:
        cache.put("expired", RESPONSE)
        cache.db.execute("UPDATE answers SET expires=? WHERE key=?", (time.time() - 1, "expired"))
        cache.db.commit()
        assert cache.get("expired", Q) is None
        cache.db.execute("INSERT INTO answers VALUES (?,?,?)", ("bad", time.time() + 30, b"{nonsense"))
        cache.db.commit()
        assert cache.get("bad", Q) is None
        assert cache.db.execute("SELECT COUNT(*) FROM answers").fetchone()[0] == 0


def test_cache_entry_limit(tmp_path):
    with AnswerCache(tmp_path / "cache", CacheSettings(max_entries=2)) as cache:
        for key in ("a", "b", "c"):
            cache.put(key, RESPONSE)
        assert cache.db.execute("SELECT COUNT(*) FROM answers").fetchone()[0] == 2


def test_unsafe_cache_directory_is_rejected(tmp_path):
    directory = tmp_path / "public"
    directory.mkdir(mode=0o755)
    with pytest.raises(StorageError):
        AnswerCache(directory, CacheSettings())


def test_new_private_directory_is_rolled_back_when_validation_fails(tmp_path, monkeypatch):
    import jevproc.core.storage as storage

    directory = tmp_path / "parent" / "nested" / "cache"
    monkeypatch.setattr(
        storage,
        "_validate_private_directory",
        lambda _path: (_ for _ in ()).throw(StorageError("synthetic directory validation failure")),
    )
    with pytest.raises(StorageError, match="synthetic"):
        AnswerCache(directory, CacheSettings())

    assert not directory.exists()
    assert not (tmp_path / "parent" / "nested").exists()
    assert not (tmp_path / "parent").exists()


def test_existing_private_directory_is_never_rolled_back(tmp_path, monkeypatch):
    import jevproc.core.storage as storage

    directory = tmp_path / "cache"
    directory.mkdir(mode=0o700)
    marker_file = directory / "keep"
    marker_file.write_text("existing")

    monkeypatch.setattr(
        storage,
        "_validate_private_directory",
        lambda path: (_ for _ in ()).throw(StorageError("synthetic directory validation failure")),
    )
    with pytest.raises(StorageError, match="synthetic"):
        AnswerCache(directory, CacheSettings())

    assert directory.is_dir()
    assert marker_file.read_text() == "existing"


def test_cache_symlinks_are_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(StorageError):
        AnswerCache(link, CacheSettings())
    (target / "answers.sqlite3").symlink_to(tmp_path / "victim")
    with pytest.raises(OSError):
        AnswerCache(target, CacheSettings())
    assert not (tmp_path / "victim").exists()


def test_new_cache_file_is_rolled_back_when_validation_fails(tmp_path, monkeypatch):
    import jevproc.core.storage as storage

    directory = tmp_path / "cache"
    monkeypatch.setattr(
        storage,
        "_validate_cache_info",
        lambda _info: (_ for _ in ()).throw(StorageError("synthetic validation failure")),
    )
    with pytest.raises(StorageError, match="synthetic"):
        AnswerCache(directory, CacheSettings())
    assert not (directory / "answers.sqlite3").exists()


def test_existing_invalid_cache_file_is_never_deleted(tmp_path):
    directory = tmp_path / "cache"
    directory.mkdir(mode=0o700)
    path = directory / "answers.sqlite3"
    path.write_bytes(b"existing")
    path.chmod(0o644)

    with pytest.raises(StorageError):
        AnswerCache(directory, CacheSettings())
    assert path.read_bytes() == b"existing"


def test_snapshot_writes_are_private_and_exclusive(tmp_path):
    path = tmp_path / "snapshot.json"
    write_private(path, b"safe")
    assert path.read_bytes() == b"safe"
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        write_private(path, b"replace")
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(FileExistsError):
        write_private(link, b"replace")
    assert path.read_bytes() == b"safe"
