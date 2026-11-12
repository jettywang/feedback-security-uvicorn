from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, TypeAlias

import httpx2
import pytest
from websockets.asyncio.client import connect

from tests.response import Response
from tests.utils import run_server
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from uvicorn.protocols.utils import DIRECT_CLIENT_EXTENSION, get_client_security_summary, get_direct_client_addr

if TYPE_CHECKING:
    from uvicorn.protocols.http.h11_impl import H11Protocol
    from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
    from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol
    from uvicorn.protocols.websockets.wsproto_impl import WSProtocol as _WSProtocol

    HTTPProtocol: TypeAlias = "type[H11Protocol | HttpToolsProtocol]"
    WSProtocol: TypeAlias = "type[WebSocketsSansIOProtocol | _WSProtocol]"

pytestmark = pytest.mark.anyio

FORWARDED_CLIENT = "203.0.113.7"


@contextlib.contextmanager
def caplog_for_logger(caplog: pytest.LogCaptureFixture, logger_name: str) -> Iterator[pytest.LogCaptureFixture]:
    logger = logging.getLogger(logger_name)
    logger.propagate, old_propagate = False, logger.propagate
    logger.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        logger.removeHandler(caplog.handler)
        logger.propagate = old_propagate


async def audit_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
    assert scope["type"] == "http"
    summary = get_client_security_summary(scope)
    response = Response(json.dumps(summary), media_type="application/json")
    await response(scope, receive, send)


async def test_direct_connection_security_summary(http_protocol_cls: HTTPProtocol, unused_tcp_port: int) -> None:
    """A direct connection: the effective address *is* the direct peer."""
    config = Config(app=audit_app, http=http_protocol_cls, lifespan="off", port=unused_tcp_port)
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(f"http://127.0.0.1:{unused_tcp_port}/")
    assert response.status_code == 200
    summary = response.json()
    assert summary["effective"].startswith("127.0.0.1:")
    assert summary["direct"] == summary["effective"]
    assert summary["proxied"] is False


async def test_untrusted_forwarded_headers_are_ignored(http_protocol_cls: HTTPProtocol, unused_tcp_port: int) -> None:
    """Forwarded headers from an untrusted peer must not change either summary."""
    config = Config(
        app=audit_app,
        http=http_protocol_cls,
        lifespan="off",
        port=unused_tcp_port,
        forwarded_allow_ips="10.0.0.1",
    )
    async with run_server(config):
        async with httpx2.AsyncClient() as client:
            response = await client.get(
                f"http://127.0.0.1:{unused_tcp_port}/", headers={"X-Forwarded-For": FORWARDED_CLIENT}
            )
    assert response.status_code == 200
    summary = response.json()
    assert summary["effective"].startswith("127.0.0.1:")
    assert summary["direct"] == summary["effective"]
    assert summary["proxied"] is False


async def test_trusted_proxy_security_summary(
    http_protocol_cls: HTTPProtocol,
    unused_tcp_port: int,
    caplog: pytest.LogCaptureFixture,
    logging_config: dict[str, Any],
) -> None:
    """A fake trusted proxy: the access log shows the resolved address, while
    the audit summary still exposes the direct peer."""
    config = Config(
        app=audit_app, http=http_protocol_cls, lifespan="off", port=unused_tcp_port, log_config=logging_config
    )
    with caplog_for_logger(caplog, "uvicorn.access"):
        async with run_server(config):
            async with httpx2.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{unused_tcp_port}/", headers={"X-Forwarded-For": FORWARDED_CLIENT}
                )
    assert response.status_code == 200
    summary = response.json()
    assert summary["effective"] == f"{FORWARDED_CLIENT}:0"
    assert summary["direct"].startswith("127.0.0.1:")
    assert summary["proxied"] is True

    access_messages = [record.message for record in caplog.records if record.name == "uvicorn.access"]
    assert len(access_messages) == 1
    # The access log shows the effective (proxy-resolved) address...
    assert access_messages[0].startswith(f'{FORWARDED_CLIENT}:0 - "GET / HTTP/1.1" 200')
    # ...and never the direct peer, which only the audit summary reveals.
    assert not access_messages[0].startswith("127.0.0.1:")


async def test_websocket_security_summary_across_upgrade(
    ws_protocol_cls: WSProtocol, http_protocol_cls: HTTPProtocol, unused_tcp_port: int
) -> None:
    """The audit identity is attached to the connection: the same summary is
    visible before the WebSocket handshake is accepted and after the upgrade."""
    summaries: list[dict[str, Any]] = []

    async def websocket_app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        assert scope["type"] == "websocket"
        message = await receive()
        assert message["type"] == "websocket.connect"
        # Pre-upgrade: the handshake has been received but not yet accepted.
        summaries.append(get_client_security_summary(scope))  # type: ignore[arg-type]
        await send({"type": "websocket.accept"})
        # Post-upgrade: same connection, same scope object.
        summaries.append(get_client_security_summary(scope))  # type: ignore[arg-type]
        await send({"type": "websocket.send", "text": json.dumps(summaries[0])})
        await send({"type": "websocket.close"})

    config = Config(app=websocket_app, ws=ws_protocol_cls, http=http_protocol_cls, lifespan="off", port=unused_tcp_port)
    async with run_server(config):
        url = f"ws://127.0.0.1:{unused_tcp_port}/"
        async with connect(url, additional_headers={"X-Forwarded-For": FORWARDED_CLIENT}) as websocket:
            data = json.loads(await websocket.recv())

    assert len(summaries) == 2
    # The summary reported to the client (pre-upgrade) matches the post-upgrade one.
    assert summaries[0] == data
    assert summaries[0] == summaries[1]
    assert summaries[0]["effective"] == f"{FORWARDED_CLIENT}:0"
    assert summaries[0]["direct"].startswith("127.0.0.1:")
    assert summaries[0]["proxied"] is True


def _handshake_scope(client: tuple[str, int], headers: list[tuple[bytes, bytes]]) -> dict[str, Any]:
    """Scope as built by Uvicorn's protocols: direct peer recorded in the extension."""
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "scheme": "http",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "client": client,
        "server": ("127.0.0.1", 8000),
        "headers": headers,
        "extensions": {DIRECT_CLIENT_EXTENSION: {"client": client}},
    }


async def _run_middleware(scope: dict[str, Any], trusted_hosts: str) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        captured.update(get_client_security_summary(scope))  # type: ignore[arg-type]

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        pass

    await ProxyHeadersMiddleware(app, trusted_hosts=trusted_hosts)(scope, receive, send)  # type: ignore[arg-type]
    return captured


async def test_summary_with_fake_trusted_proxy() -> None:
    """Fake trusted proxy: headers resolve the effective address, the extension
    keeps the proxy itself as the direct peer."""
    proxy_addr = ("10.0.0.1", 51000)
    scope = _handshake_scope(proxy_addr, [(b"x-forwarded-for", FORWARDED_CLIENT.encode())])
    summary = await _run_middleware(scope, trusted_hosts="10.0.0.1")
    assert summary == {"direct": "10.0.0.1:51000", "effective": f"{FORWARDED_CLIENT}:0", "proxied": True}
    # The normal application interface keeps using the effective address.
    assert scope["client"] == (FORWARDED_CLIENT, 0)


async def test_summary_with_direct_connection() -> None:
    """Direct connection: the peer is not trusted, headers are ignored, and
    both summaries describe the connecting party."""
    client_addr = ("203.0.113.9", 1234)
    scope = _handshake_scope(client_addr, [(b"x-forwarded-for", FORWARDED_CLIENT.encode())])
    summary = await _run_middleware(scope, trusted_hosts="10.0.0.1")
    assert summary == {"direct": "203.0.113.9:1234", "effective": "203.0.113.9:1234", "proxied": False}
    assert scope["client"] == client_addr


def test_direct_client_addr_falls_back_to_scope_client() -> None:
    """Scopes not created by Uvicorn's protocols fall back to ``scope["client"]``."""
    scope: Any = {"type": "http", "client": ("10.1.2.3", 4321)}
    assert get_direct_client_addr(scope) == "10.1.2.3:4321"
    assert get_client_security_summary(scope) == {
        "direct": "10.1.2.3:4321",
        "effective": "10.1.2.3:4321",
        "proxied": False,
    }


def test_direct_client_extension_key_is_stable() -> None:
    assert DIRECT_CLIENT_EXTENSION == "uvicorn.direct_client"
