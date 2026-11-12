from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import Sequence

import pytest

from uvicorn._tls import TLSConfigurationError, validate_listeners_tls
from uvicorn.config import Config
from uvicorn.server import Server

pytestmark = pytest.mark.anyio


class RecordingSocket:
    """Socket double that only records the calls the TLS policy makes."""

    def __init__(self, family: int, sockname: str | tuple) -> None:
        self.family = family
        self._sockname = sockname
        self.calls: list[str] = []
        self.closed = False

    def getsockname(self) -> str | tuple:
        self.calls.append("getsockname")
        return self._sockname

    def close(self) -> None:
        self.calls.append("close")
        self.closed = True


class FakeAsyncioServer:
    def __init__(self, sockets: Sequence[RecordingSocket]) -> None:
        self.sockets = list(sockets)
        self.closed = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _make_app():
    state = {"lifespan_started": False, "lifespan_shutdown": False}

    async def app(scope, receive, send):
        if scope["type"] != "lifespan":
            return
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                state["lifespan_started"] = True
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                state["lifespan_shutdown"] = True
                await send({"type": "lifespan.shutdown.complete"})
                return

    return app, state


def _make_server(monkeypatch: pytest.MonkeyPatch, *, ssl_enabled: bool, host: str = "127.0.0.1"):
    app, state = _make_app()
    config = Config(app=app, host=host, port=8443, lifespan="on", loop="asyncio")
    config.load()
    if ssl_enabled:
        config.ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    created_sockets: list[RecordingSocket] = []

    async def fake_create_server(self, protocol_factory, **kwargs):
        sock = kwargs.get("sock")
        if sock is not None:
            created_sockets.append(sock)
            return FakeAsyncioServer([sock])
        new_sock = RecordingSocket(socket.AF_INET, (host, 8443))
        created_sockets.append(new_sock)
        return FakeAsyncioServer([new_sock])

    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "create_server", fake_create_server)
    return Server(config=config), state, created_sockets


def test_loopback_listener_allowed_without_tls() -> None:
    sock = RecordingSocket(socket.AF_INET, ("127.0.0.1", 8000))
    validate_listeners_tls([sock], ssl_enabled=False)
    assert sock.calls == ["getsockname"]


def test_ipv6_loopback_listener_allowed_without_tls() -> None:
    sock = RecordingSocket(socket.AF_INET6, ("::1", 8000, 0, 0))
    validate_listeners_tls([sock], ssl_enabled=False)
    assert sock.calls == ["getsockname"]


def test_unix_socket_allowed_without_tls() -> None:
    sock = RecordingSocket(socket.AF_UNIX, "/tmp/uvicorn.sock")
    validate_listeners_tls([sock], ssl_enabled=False)
    assert sock.calls == ["getsockname"]


def test_public_listener_rejected_without_tls() -> None:
    sock = RecordingSocket(socket.AF_INET, ("203.0.113.5", 8443))
    with pytest.raises(TLSConfigurationError, match=r"203\.0\.113\.5:8443") as exc_info:
        validate_listeners_tls([sock], ssl_enabled=False)
    assert "Refusing to start listener" in str(exc_info.value)
    assert sock.calls == ["getsockname"]


def test_public_ipv6_listener_rejected_without_tls() -> None:
    sock = RecordingSocket(socket.AF_INET6, ("2001:db8::1", 8443, 0, 0))
    with pytest.raises(TLSConfigurationError, match=r"\[2001:db8::1\]:8443"):
        validate_listeners_tls([sock], ssl_enabled=False)


def test_public_listener_allowed_when_tls_enabled() -> None:
    sock = RecordingSocket(socket.AF_INET, ("203.0.113.5", 8443))
    validate_listeners_tls([sock], ssl_enabled=True)
    assert sock.calls == []


async def test_passed_public_socket_rejected_before_app_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    server, state, _ = _make_server(monkeypatch, ssl_enabled=False)
    public_sock = RecordingSocket(socket.AF_INET, ("203.0.113.5", 8443))

    with pytest.raises(TLSConfigurationError, match=r"203\.0\.113\.5:8443"):
        await server.serve(sockets=[public_sock])

    assert state["lifespan_started"] is False
    assert public_sock.calls == ["getsockname"]
    assert server.started is False


async def test_created_public_listener_rejected_before_app_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    server, state, created_sockets = _make_server(monkeypatch, ssl_enabled=False, host="203.0.113.5")

    with pytest.raises(TLSConfigurationError, match=r"203\.0\.113\.5:8443"):
        await server.serve()

    assert state["lifespan_started"] is False
    assert created_sockets and created_sockets[0].calls == ["getsockname"]
    assert server.started is False


async def test_passed_loopback_socket_starts_and_shuts_down(monkeypatch: pytest.MonkeyPatch) -> None:
    server, state, _ = _make_server(monkeypatch, ssl_enabled=False)
    local_sock = RecordingSocket(socket.AF_INET, ("127.0.0.1", 8443))

    server.lifespan = server.config.lifespan_class(server.config)
    await server.startup(sockets=[local_sock])
    assert state["lifespan_started"] is True
    assert server.started is True

    await server.shutdown(sockets=[local_sock])
    assert state["lifespan_shutdown"] is True
    assert local_sock.closed is True


async def test_public_listener_with_tls_starts(monkeypatch: pytest.MonkeyPatch) -> None:
    server, state, _ = _make_server(monkeypatch, ssl_enabled=True, host="203.0.113.5")

    server.lifespan = server.config.lifespan_class(server.config)
    await server.startup()
    assert state["lifespan_started"] is True
    assert server.started is True

    await server.shutdown()
    assert state["lifespan_shutdown"] is True
