"""Bounded async transport with shared pacing, safe failures and a hard attempt budget."""

import asyncio
import math
import secrets
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Self
from urllib.parse import urlsplit

import httpx

from jevproc import __version__
from jevproc.core.config import JevSettings, Question
from jevproc.core.protocol import (
    BudgetError,
    ContextLimitError,
    JevError,
    JevResponse,
    RequestRejectedError,
    validate_response,
)


class Limiter:
    def __init__(self, rpm: float):
        self.interval = 60 / rpm if rpm else 0
        self.next_start = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            loop = asyncio.get_running_loop()
            while (delay := self.next_start - loop.time()) > 0:
                await asyncio.sleep(delay)
            self.next_start = loop.time() + self.interval

    def defer(self, delay: float) -> None:
        self.next_start = max(self.next_start, asyncio.get_running_loop().time() + delay)


def endpoint(value: str) -> str:
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError as exc:
        raise JevError("invalid TYPESAFE_BASE_URL origin") from exc
    if (
        not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise JevError("TYPESAFE_BASE_URL must be an origin without credentials, path, query or fragment")
    if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}):
        raise JevError("TYPESAFE_BASE_URL requires HTTPS except for a loopback test server")
    return value.rstrip("/")


def retry_after(headers: httpx.Headers) -> float | None:
    try:
        if "retry-after-ms" in headers:
            value = float(headers["retry-after-ms"]) / 1000
        elif "retry-after" in headers:
            raw = headers["retry-after"]
            try:
                value = float(raw)
            except ValueError:
                moment = parsedate_to_datetime(raw)
                if moment.tzinfo is None:
                    moment = moment.replace(tzinfo=UTC)
                value = (moment - datetime.now(UTC)).total_seconds()
        else:
            return None
        return max(0.0, value) if math.isfinite(value) else None
    except (ValueError, TypeError, OverflowError):
        return None


def _safe_request_id(response: httpx.Response) -> str:
    value = response.headers.get("x-typesafe-request-id", "")[:100]
    return "".join(char for char in value if char.isalnum() or char in "-_")


def _safe_machine_value(value: object) -> str | None:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, str) or not 1 <= len(value) <= 80:
        return None
    return value if all(char.isalnum() or char in "._:-" for char in value) else None


_MACHINE_FIELD_KEYS = frozenset({"code", "type", "status", "error"})


def _machine_items(body: object) -> Iterator[tuple[str, str]]:
    """Iteratively walk bounded response structure and yield safe machine fields."""
    pending = [body]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for raw_key, child in value.items():
                key = str(raw_key)
                if key in _MACHINE_FIELD_KEYS:
                    safe = _safe_machine_value(child)
                    if safe is not None:
                        yield key, safe
                pending.append(child)
        elif isinstance(value, list):
            pending.extend(reversed(value[:64]))


def _machine_fields(body: object) -> dict[str, tuple[str, ...]]:
    found: dict[str, set[str]] = {}
    for key, value in _machine_items(body):
        found.setdefault(key, set()).add(value)
    return {key: tuple(sorted(values)) for key, values in sorted(found.items())}


def _json_body(response: httpx.Response) -> object:
    try:
        return response.json()
    except ValueError:
        return None


def _context_error(response: httpx.Response) -> bool:
    if response.status_code == 413:
        return True
    if response.status_code not in {400, 422}:
        return False
    fields = _machine_fields(_json_body(response))
    return any(
        value in {"max_tokens_exceeded", "context_length_exceeded", "content_too_large"}
        for values in fields.values()
        for value in values
    )


@dataclass(frozen=True)
class _Retry:
    delay: float
    defer_shared: bool = False


class JevClient:
    def __init__(
        self,
        settings: JevSettings,
        api_key: str,
        *,
        base_url: str = "https://api.typesafe.ai",
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        if not api_key.strip():
            raise JevError("set TYPESAFE_API_KEY for live analysis, or use --offline or --demo")
        if any(ord(char) < 33 or ord(char) > 126 for char in api_key):
            raise JevError("TYPESAFE_API_KEY contains invalid header characters")
        self.settings = settings
        self.base_url = endpoint(base_url)
        self.requests = 0
        self.retries = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.fatal_error: str | None = None
        self.limiter = Limiter(settings.requests_per_minute)
        self.slots = asyncio.Semaphore(settings.concurrency)
        self.http = httpx.AsyncClient(
            base_url=self.base_url,
            transport=transport,
            timeout=settings.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=settings.concurrency, max_keepalive_connections=settings.concurrency),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"jevproc/{__version__}",
            },
        )

    def _check_ready(self) -> None:
        if self.fatal_error:
            raise JevError(self.fatal_error)
        if self.requests >= self.settings.max_requests:
            raise BudgetError("Jev request-attempt budget exhausted; remaining processes were not analyzed")

    async def _post(self, body: bytes) -> httpx.Response:
        async with self.slots:
            self._check_ready()
            await self.limiter.acquire()
            self._check_ready()
            self.requests += 1
            async with self.http.stream("POST", "/v1/systemone", content=body) as response:
                result = await _read_bounded_response(response)
            if result.status_code in {401, 403}:
                self.fatal_error = f"Jev authentication/authorization failed (HTTP {result.status_code})"
            return result

    async def evaluate(self, body: bytes, questions: Mapping[str, Question]) -> JevResponse:
        for attempt in range(self.settings.retries + 1):
            outcome = await self._attempt(body, questions, attempt)
            if isinstance(outcome, JevResponse):
                return outcome
            await self._wait_before_retry(outcome)
        raise AssertionError("retry loop must return or raise")

    async def _attempt(
        self,
        body: bytes,
        questions: dict[str, Question],
        attempt: int,
    ) -> JevResponse | _Retry:
        try:
            response = await self._post(body)
        except httpx.RequestError as exc:
            return _Retry(self._transport_retry(exc, attempt))
        if response.is_success:
            return self._accept_response(response, questions)
        return _Retry(self._response_retry(response, attempt), defer_shared=True)

    async def _wait_before_retry(self, retry: _Retry) -> None:
        if retry.defer_shared:
            self.limiter.defer(retry.delay)
        self.retries += 1
        await asyncio.sleep(retry.delay)

    def _accept_response(self, response: httpx.Response, questions: dict[str, Question]) -> JevResponse:
        validated = validate_response(response.content, questions)
        if self.settings.model not in {"jev-latest", "jev-preview"} and validated.model != self.settings.model:
            raise JevError("Jev returned a different model than the requested pinned version")
        self.input_tokens += validated.usage.input_tokens
        self.output_tokens += validated.usage.output_tokens
        return validated

    def _transport_retry(self, error: httpx.RequestError, attempt: int) -> float:
        if attempt == self.settings.retries:
            raise JevError(f"Jev transport failed ({type(error).__name__}); no response was classified") from error
        return self._backoff(attempt)

    def _response_retry(self, response: httpx.Response, attempt: int) -> float:
        _raise_permanent_failure(response)
        if attempt == self.settings.retries:
            raise JevError(f"Jev retries exhausted (HTTP {response.status_code})")
        provider_delay = retry_after(response.headers)
        delay = self._backoff(attempt) if provider_delay is None else provider_delay
        if delay > self.settings.max_retry_delay:
            raise JevError("Jev Retry-After exceeds max_retry_delay; refusing to retry early")
        return delay

    def _backoff(self, attempt: int) -> float:
        return min(self.settings.max_retry_delay, 0.5 * 2**attempt + secrets.randbelow(200_000) / 1_000_000)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.http.aclose()


async def _read_bounded_response(response: httpx.Response) -> httpx.Response:
    """Consume and detach a decoded response without retaining transport resources."""
    parts: list[bytes] = []
    size = 0
    async for part in response.aiter_bytes(chunk_size=65536):
        size += len(part)
        if size > 2 * 1024 * 1024:
            raise JevError("Jev response exceeds the 2 MiB safety limit")
        parts.append(part)
    headers = response.headers.copy()
    headers.pop("content-encoding", None)
    headers.pop("content-length", None)
    return httpx.Response(response.status_code, headers=headers, content=b"".join(parts))


def _raise_permanent_failure(response: httpx.Response) -> None:
    if _context_error(response):
        raise ContextLimitError("Jev rejected the context size")
    if response.status_code in {400, 422}:
        raise RequestRejectedError(
            status=response.status_code,
            machine_fields=_machine_fields(_json_body(response)),
            request_id=_safe_request_id(response),
        )
    if response.status_code not in {408, 429} and response.status_code < 500:
        request_id = _safe_request_id(response)
        suffix = f"; request-id={request_id}" if request_id else ""
        raise JevError(f"Jev request failed (HTTP {response.status_code}{suffix})")
