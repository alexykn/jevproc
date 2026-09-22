"""Bounded async transport with shared pacing, safe failures and a hard attempt budget."""

import asyncio
import math
import random
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Self
from urllib.parse import urlsplit

import httpx

from jevproc import __version__
from jevproc.core.config import JevSettings, Question
from jevproc.core.protocol import BudgetError, ContextLimitError, JevError, JevResponse, validate_response


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
    if (not parts.hostname or parts.username or parts.password or parts.query or parts.fragment
        or parts.path not in {"", "/"}):
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


def _context_error(response: httpx.Response) -> bool:
    if response.status_code == 413:
        return True
    if response.status_code not in {400, 422}:
        return False
    try:
        body = response.json()
    except ValueError:
        return False
    if not isinstance(body, dict):
        return False
    fields = [body, body.get("error")]
    return any(isinstance(item, dict) and item.get("code") in {"max_tokens_exceeded", "context_length_exceeded"}
               for item in fields)


class JevClient:
    def __init__(self, settings: JevSettings, api_key: str, *, base_url: str = "https://api.typesafe.ai",
                 transport: httpx.AsyncBaseTransport | None = None):
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
        self.http = httpx.AsyncClient(
            base_url=self.base_url, transport=transport,
            timeout=settings.timeout_seconds, follow_redirects=False, trust_env=False,
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json",
                     "Accept": "application/json", "User-Agent": f"jevproc/{__version__}"},
        )

    def _check_ready(self) -> None:
        if self.fatal_error:
            raise JevError(self.fatal_error)
        if self.requests >= self.settings.max_requests:
            raise BudgetError("Jev request-attempt budget exhausted; remaining processes were not analyzed")

    async def _post(self, body: bytes) -> httpx.Response:
        self._check_ready()
        await self.limiter.acquire()
        self._check_ready()
        self.requests += 1
        async with self.http.stream("POST", "/v1/systemone", content=body) as response:
            parts: list[bytes] = []
            size = 0
            async for part in response.aiter_bytes(chunk_size=65536):
                size += len(part)
                if size > 2 * 1024 * 1024:
                    raise JevError("Jev response exceeds the 2 MiB safety limit")
                parts.append(part)
            # Keep a bounded response for decoding after the connection is closed.
            headers = response.headers.copy()
            # aiter_bytes already decoded the transport encoding; do not decode it twice.
            headers.pop("content-encoding", None)
            headers.pop("content-length", None)
            result = httpx.Response(response.status_code, headers=headers, content=b"".join(parts))
            if response.status_code in {401, 403}:
                self.fatal_error = f"Jev authentication/authorization failed (HTTP {response.status_code})"
            return result

    async def evaluate(self, body: bytes, questions: dict[str, Question]) -> JevResponse:
        for attempt in range(self.settings.retries + 1):
            try:
                response = await self._post(body)
            except httpx.RequestError as exc:
                if attempt == self.settings.retries:
                    raise JevError(f"Jev transport failed ({type(exc).__name__}); no response was classified") from exc
                delay = self._backoff(attempt)
            else:
                if response.is_success:
                    validated = validate_response(response.content, questions)
                    if self.settings.model not in {"jev-latest", "jev-preview"} and validated.model != self.settings.model:
                        raise JevError("Jev returned a different model than the requested pinned version")
                    self.input_tokens += validated.usage.input_tokens
                    self.output_tokens += validated.usage.output_tokens
                    return validated
                if _context_error(response):
                    raise ContextLimitError("Jev rejected the context size")
                if response.status_code not in {408, 429} and response.status_code < 500:
                    raise JevError(f"Jev request failed (HTTP {response.status_code})")
                if attempt == self.settings.retries:
                    raise JevError(f"Jev retries exhausted (HTTP {response.status_code})")
                provider_delay = retry_after(response.headers)
                delay = self._backoff(attempt) if provider_delay is None else provider_delay
                if delay > self.settings.max_retry_delay:
                    raise JevError("Jev Retry-After exceeds max_retry_delay; refusing to retry early")
                # All workers honor overload delays rather than just the worker that hit the limit.
                self.limiter.defer(delay)
            self.retries += 1
            await asyncio.sleep(delay)
        raise AssertionError("retry loop must return or raise")

    def _backoff(self, attempt: int) -> float:
        return min(self.settings.max_retry_delay, 0.5 * 2 ** attempt + random.random() * 0.2)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.http.aclose()
