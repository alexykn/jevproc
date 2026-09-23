"""Shared bounded access semantics for psutil-backed evidence reads."""

from collections.abc import Callable
from typing import Any

import psutil

from jevproc.core.models import Coverage

_FAILURE_COVERAGE = (
    (psutil.AccessDenied, "denied"),
    ((psutil.NoSuchProcess, psutil.ZombieProcess), "gone"),
    ((OSError, NotImplementedError, AttributeError), "unavailable"),
)


def failure_coverage(exc: BaseException) -> Coverage:
    return next(state for types, state in _FAILURE_COVERAGE if isinstance(exc, types))


def observed(action: Callable[[], Any], default: Any = None) -> tuple[Any, Coverage]:
    try:
        return action(), "observed"
    except (
        psutil.AccessDenied,
        psutil.NoSuchProcess,
        psutil.ZombieProcess,
        OSError,
        NotImplementedError,
        AttributeError,
    ) as exc:
        return default, failure_coverage(exc)
