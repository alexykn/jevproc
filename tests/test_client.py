import gzip
import json
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from jevproc.core.client import JevClient, _machine_fields, endpoint, retry_after
from jevproc.core.config import JevSettings, NoulQuestion
from jevproc.core.protocol import BudgetError, ContextLimitError, JevError, NoulAnswer, RequestRejectedError, encode

Q = {"q": NoulQuestion(type="noul", instructions="Is the evidence suspicious?")}
BODY = encode({"model": "jev-1.13.0", "state": "synthetic", "questions": {"q": Q["q"].model_dump(exclude_none=True)}})
OK = {
    "model": "jev-1.13.0",
    "answers": {"q": {"type": "noul", "noul": 0.2}},
    "usage": {"input_tokens": 100, "output_tokens": 2},
}


def settings(**changes):
    return JevSettings(requests_per_minute=0, max_retry_delay=0, **changes)


async def test_wire_and_success():
    def handler(_request):
        assert request.url.path == "/v1/systemone"
        assert request.headers["authorization"] == "Bearer test-only-key"
        assert json.loads(request.content)["state"] == "synthetic"
        return httpx.Response(200, json=OK)

    async with JevClient(settings(), "test-only-key", transport=httpx.MockTransport(handler)) as client:
        result = await client.evaluate(BODY, Q)
        answer = result.answers["q"]
        assert isinstance(answer, NoulAnswer)
        assert answer.noul == 0.2
        assert client.requests == 1 and client.input_tokens == 100


@pytest.mark.parametrize("status", [408, 429, 500, 529])
async def test_transient_retries_count_against_budget(status):
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        return httpx.Response(status, headers={"retry-after": "0"}) if calls == 1 else httpx.Response(200, json=OK)

    async with JevClient(settings(retries=1), "key", transport=httpx.MockTransport(handler)) as client:
        await client.evaluate(BODY, Q)
        assert client.requests == 2 and client.retries == 1


@pytest.mark.parametrize("status", [301, 302, 400, 401, 403, 422])
async def test_permanent_errors_not_retried_and_bodies_not_logged(status):
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            status, headers={"location": "https://attacker.invalid"}, text="PRIVATE-RESPONSE-CONTENT"
        )
    )
    async with JevClient(settings(), "PRIVATE-API-KEY", transport=transport) as client:
        with pytest.raises(JevError) as exc:
            await client.evaluate(BODY, Q)
        assert "PRIVATE" not in str(exc.value)
        assert client.requests == 1


async def test_attempt_budget_includes_retries():
    transport = httpx.MockTransport(lambda _request: httpx.Response(429, headers={"retry-after": "0"}))
    async with JevClient(settings(max_requests=1, retries=3), "key", transport=transport) as client:
        with pytest.raises(BudgetError):
            await client.evaluate(BODY, Q)
        assert client.requests == 1


async def test_long_retry_after_stops_instead_of_retrying_early():
    transport = httpx.MockTransport(lambda _request: httpx.Response(429, headers={"retry-after": "1000"}))
    async with JevClient(settings(), "key", transport=transport) as client:
        with pytest.raises(JevError, match="refusing to retry early"):
            await client.evaluate(BODY, Q)
        assert client.requests == 1


async def test_timeout_is_sanitized():
    def handler(_request):
        raise httpx.ReadTimeout("PRIVATE-KEY-IN-EXCEPTION")

    async with JevClient(settings(retries=0), "key", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(JevError) as exc:
            await client.evaluate(BODY, Q)
        assert "PRIVATE" not in str(exc.value)
        assert "ReadTimeout" in str(exc.value)


@pytest.mark.parametrize(
    "status,body",
    [
        (413, {}),
        (422, {"error": {"code": "max_tokens_exceeded"}}),
        (400, {"error": {"details": [{"code": "max_tokens_exceeded"}]}}),
    ],
)
async def test_recognized_context_limit(status, body):
    async with JevClient(
        settings(), "key", transport=httpx.MockTransport(lambda _request: httpx.Response(status, json=body))
    ) as client:
        with pytest.raises(ContextLimitError):
            await client.evaluate(BODY, Q)
        assert client.requests == 1


def test_machine_fields_walk_nested_structures_without_leaking_prose():
    body = {
        "error": {
            "details": [
                {"code": "context_length_exceeded", "message": "PRIVATE TEXT"},
                {"status": "too_large"},
            ],
            "type": "invalid_request",
        }
    }
    assert _machine_fields(body) == {
        "code": ("context_length_exceeded",),
        "status": ("too_large",),
        "type": ("invalid_request",),
    }


async def test_generic_400_exposes_only_safe_machine_fields():
    body = {"error": {"code": "invalid_request", "message": "PRIVATE RESPONSE TEXT"}, "status": "bad_request"}
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            400,
            headers={"x-typesafe-request-id": "req_ABC-123"},
            json=body,
        )
    )
    async with JevClient(settings(), "key", transport=transport) as client:
        with pytest.raises(RequestRejectedError) as exc:
            await client.evaluate(BODY, Q)
    text = str(exc.value)
    assert "invalid_request" in text and "bad_request" in text
    assert "req_ABC-123" in text
    assert "PRIVATE" not in text


async def test_model_pin_is_enforced():
    async with JevClient(
        settings(),
        "key",
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={**OK, "model": "jev-9.9.9"})),
    ) as client:
        with pytest.raises(JevError, match="different model"):
            await client.evaluate(BODY, Q)


async def test_gzip_response_is_not_double_decoded():
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(200, headers={"content-encoding": "gzip"}, content=gzip.compress(encode(OK)))
    )
    async with JevClient(settings(), "key", transport=transport) as client:
        answer = (await client.evaluate(BODY, Q)).answers["q"]
        assert isinstance(answer, NoulAnswer)
        assert answer.noul == 0.2


async def test_response_size_bound():
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, content=b"x" * (2 * 1024 * 1024 + 1)))
    async with JevClient(settings(), "key", transport=transport) as client:
        with pytest.raises(JevError, match="2 MiB"):
            await client.evaluate(BODY, Q)


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.com",
        "https://u:p@example.com",
        "https://example.com/path",
        "https://example.com?secret=yes",
        "https://example.com#fragment",
        "https://",
        "https://example.com:invalid",
    ],
)
def test_endpoint_rejects_unsafe_origins(origin):
    with pytest.raises(JevError):
        endpoint(origin)


@pytest.mark.parametrize(
    "origin", ["https://api.typesafe.ai", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"]
)
def test_safe_origins(origin):
    assert endpoint(origin + "/") == origin


def test_retry_after_formats():
    assert retry_after(httpx.Headers({"retry-after-ms": "500"})) == 0.5
    assert retry_after(httpx.Headers({"retry-after": "3"})) == 3
    assert retry_after(httpx.Headers({"retry-after": "NaN"})) is None
    future = format_datetime(datetime.now(UTC) + timedelta(seconds=30))
    delay = retry_after(httpx.Headers({"retry-after": future}))
    assert delay is not None
    assert 28 <= delay <= 30


@pytest.mark.parametrize("status", [200, 401])
async def test_stopped_client_does_not_wait_for_rate_limiter(status, monkeypatch):
    transport = httpx.MockTransport(lambda _request: httpx.Response(status, json=OK))
    async with JevClient(settings(max_requests=1), "key", transport=transport) as client:
        if status == 200:
            await client.evaluate(BODY, Q)
        else:
            with pytest.raises(JevError):
                await client.evaluate(BODY, Q)

        async def forbidden_wait():
            pytest.fail("a stopped client should fail before pacing another request")

        monkeypatch.setattr(client.limiter, "acquire", forbidden_wait)
        with pytest.raises(JevError):
            await client.evaluate(BODY, Q)
