"""Bounded execution of the few fixed OS inspection tools jevproc trusts."""

import os
import signal
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

AllowedExecutable = Literal["/bin/ps", "/usr/bin/codesign"]


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def _wait_for_process(pid: int, timeout: float) -> int | None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except InterruptedError:
            continue
        if waited == pid:
            return os.waitstatus_to_exitcode(status)
        if time.monotonic() >= deadline:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            return None
        time.sleep(0.01)


def run_fixed(
    executable: AllowedExecutable,
    arguments: Sequence[str],
    *,
    timeout: float,
) -> CommandResult | None:
    """Run an allowlisted absolute executable without a shell and with bounded lifetime."""
    argv = [executable, *arguments]
    with (
        open(os.devnull, "rb") as stdin,
        tempfile.TemporaryFile() as stdout,
        tempfile.TemporaryFile() as stderr,
    ):
        file_actions = [
            (os.POSIX_SPAWN_DUP2, stdin.fileno(), 0),
            (os.POSIX_SPAWN_DUP2, stdout.fileno(), 1),
            (os.POSIX_SPAWN_DUP2, stderr.fileno(), 2),
        ]
        try:
            pid = os.posix_spawn(executable, argv, os.environ.copy(), file_actions=file_actions)
        except OSError:
            return None
        returncode = _wait_for_process(pid, timeout)
        if returncode is None:
            return None
        stdout.seek(0)
        stderr.seek(0)
        return CommandResult(
            returncode=returncode,
            stdout=stdout.read().decode("utf-8", errors="replace"),
            stderr=stderr.read().decode("utf-8", errors="replace"),
        )
