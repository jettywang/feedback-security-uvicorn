import httpx2
import pytest

from tests.middleware.test_logging import caplog_for_logger
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.logging import TRACE_LOG_LEVEL
from uvicorn.middleware.message_logger import MessageLoggerMiddleware

SECRET = "business-payload-secret"


def collector_view(caplog: pytest.LogCaptureFixture) -> "list[tuple[str | None, str | None]]":
    """The structured view a log collector would read from the records."""
    return [(record.asgi_direction, getattr(record, "asgi_event", None)) for record in caplog.records]  # type: ignore


def assert_no_payload_leak(caplog: pytest.LogCaptureFixture) -> None:
    for record in caplog.records:
        assert SECRET not in record.getMessage()
        assert SECRET not in repr(record.asgi_connection)  # type: ignore
        assert SECRET not in repr(record.asgi_direction)  # type: ignore
        assert SECRET not in repr(getattr(record, "asgi_event", None))


@pytest.mark.anyio
async def test_message_logger(caplog: pytest.LogCaptureFixture) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    with caplog_for_logger(caplog, "uvicorn.asgi"):
        caplog.set_level(TRACE_LOG_LEVEL, logger="uvicorn.asgi")
        caplog.set_level(TRACE_LOG_LEVEL)

        transport = httpx2.ASGITransport(MessageLoggerMiddleware(app))  # type: ignore
        async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/")
        assert response.status_code == 200
        messages = [record.msg % record.args for record in caplog.records]
        assert sum(["ASGI [1] Started" in message for message in messages]) == 1
        assert sum(["ASGI [1] Send" in message for message in messages]) == 2
        assert sum(["ASGI [1] Receive" in message for message in messages]) == 1
        assert sum(["ASGI [1] Completed" in message for message in messages]) == 1
        assert sum(["ASGI [1] Raised exception" in message for message in messages]) == 0


@pytest.mark.anyio
async def test_message_logger_exc(caplog: pytest.LogCaptureFixture) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        raise RuntimeError()

    with caplog_for_logger(caplog, "uvicorn.asgi"):
        caplog.set_level(TRACE_LOG_LEVEL, logger="uvicorn.asgi")
        caplog.set_level(TRACE_LOG_LEVEL)
        transport = httpx2.ASGITransport(MessageLoggerMiddleware(app))  # type: ignore
        async with httpx2.AsyncClient(transport=transport, base_url="http://testserver") as client:
            with pytest.raises(RuntimeError):
                await client.get("/")
        messages = [record.msg % record.args for record in caplog.records]
        assert sum(["ASGI [1] Started" in message for message in messages]) == 1
        assert sum(["ASGI [1] Send" in message for message in messages]) == 0
        assert sum(["ASGI [1] Receive" in message for message in messages]) == 0
        assert sum(["ASGI [1] Completed" in message for message in messages]) == 0
        assert sum(["ASGI [1] Raised exception" in message for message in messages]) == 1


@pytest.mark.anyio
async def test_structured_fields_http(caplog: pytest.LogCaptureFixture) -> None:
    app_received = []
    app_sent = []

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        app_received.append(await receive())
        await send({"type": "http.response.start", "status": 200, "headers": [(b"x-token", SECRET.encode())]})
        await send({"type": "http.response.body", "body": SECRET.encode(), "more_body": False})

    request_body = SECRET.encode()
    incoming = [{"type": "http.request", "body": request_body, "more_body": False}]

    async def receive() -> dict:
        return incoming.pop(0)

    async def send(message: dict) -> None:
        app_sent.append(message)

    scope = {"type": "http", "client": ("127.0.0.1", 50000), "headers": [(b"authorization", SECRET.encode())]}

    with caplog_for_logger(caplog, "uvicorn.asgi"):
        caplog.set_level(TRACE_LOG_LEVEL, logger="uvicorn.asgi")
        await MessageLoggerMiddleware(app)(scope, receive, send)  # type: ignore

    events = collector_view(caplog)
    assert events == [
        (None, "http"),  # Started
        ("receive", "http.request"),
        ("send", "http.response.start"),
        ("send", "http.response.body"),
        (None, None),  # Completed
    ]
    # The collector sees exactly the event types the application actually received and sent.
    assert [event for direction, event in events if direction == "receive"] == [m["type"] for m in app_received]
    assert [event for direction, event in events if direction == "send"] == [m["type"] for m in app_sent]
    # The connection identifier is present on every record.
    assert all(record.asgi_connection == "127.0.0.1:50000 - ASGI [1]" for record in caplog.records)  # type: ignore
    # The business payload leaves through neither output.
    assert_no_payload_leak(caplog)
    messages = [record.msg % record.args for record in caplog.records]
    assert any(f"<{len(request_body)} bytes>" in message for message in messages)


@pytest.mark.anyio
async def test_structured_fields_websocket(caplog: pytest.LogCaptureFixture) -> None:
    app_received = []
    app_sent = []

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        app_received.append(await receive())  # websocket.connect
        app_received.append(await receive())  # websocket.receive
        await send({"type": "websocket.accept", "headers": [(b"x-token", SECRET.encode())]})
        await send({"type": "websocket.send", "bytes": SECRET.encode()})
        app_received.append(await receive())  # websocket.disconnect

    incoming = [
        {"type": "websocket.connect"},
        {"type": "websocket.receive", "text": SECRET},
        {"type": "websocket.disconnect", "code": 1000},
    ]

    async def receive() -> dict:
        return incoming.pop(0)

    async def send(message: dict) -> None:
        app_sent.append(message)

    scope = {"type": "websocket", "client": ("127.0.0.1", 50001), "headers": []}

    with caplog_for_logger(caplog, "uvicorn.asgi"):
        caplog.set_level(TRACE_LOG_LEVEL, logger="uvicorn.asgi")
        await MessageLoggerMiddleware(app)(scope, receive, send)  # type: ignore

    events = collector_view(caplog)
    assert events == [
        (None, "websocket"),  # Started
        ("receive", "websocket.connect"),
        ("receive", "websocket.receive"),
        ("send", "websocket.accept"),
        ("send", "websocket.send"),
        ("receive", "websocket.disconnect"),
        (None, None),  # Completed
    ]
    assert [event for direction, event in events if direction == "receive"] == [m["type"] for m in app_received]
    assert [event for direction, event in events if direction == "send"] == [m["type"] for m in app_sent]
    assert all(record.asgi_connection == "127.0.0.1:50001 - ASGI [1]" for record in caplog.records)  # type: ignore
    assert_no_payload_leak(caplog)
    messages = [record.msg % record.args for record in caplog.records]
    assert any(f"<{len(SECRET)} chars>" in message for message in messages)
    assert any(f"<{len(SECRET.encode())} bytes>" in message for message in messages)


@pytest.mark.anyio
async def test_structured_fields_lifespan(caplog: pytest.LogCaptureFixture) -> None:
    app_received = []
    app_sent = []

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        app_received.append(await receive())  # lifespan.startup
        await send({"type": "lifespan.startup.complete"})
        app_received.append(await receive())  # lifespan.shutdown
        await send({"type": "lifespan.shutdown.complete"})

    incoming = [
        {"type": "lifespan.startup"},
        {"type": "lifespan.shutdown"},
    ]

    async def receive() -> dict:
        return incoming.pop(0)

    async def send(message: dict) -> None:
        app_sent.append(message)

    scope = {"type": "lifespan", "state": {}}

    with caplog_for_logger(caplog, "uvicorn.asgi"):
        caplog.set_level(TRACE_LOG_LEVEL, logger="uvicorn.asgi")
        await MessageLoggerMiddleware(app)(scope, receive, send)  # type: ignore

    events = collector_view(caplog)
    assert events == [
        (None, "lifespan"),  # Started
        ("receive", "lifespan.startup"),
        ("send", "lifespan.startup.complete"),
        ("receive", "lifespan.shutdown"),
        ("send", "lifespan.shutdown.complete"),
        (None, None),  # Completed
    ]
    assert [event for direction, event in events if direction == "receive"] == [m["type"] for m in app_received]
    assert [event for direction, event in events if direction == "send"] == [m["type"] for m in app_sent]
    # Lifespan has no client; the connection identifier falls back to the plain ASGI prefix.
    assert all(record.asgi_connection == "ASGI [1]" for record in caplog.records)  # type: ignore
    assert_no_payload_leak(caplog)
