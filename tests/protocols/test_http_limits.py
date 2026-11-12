from __future__ import annotations

import asyncio
from typing import Any

import pytest

from tests.protocols.test_http import SIMPLE_GET_REQUEST, MockTransport
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.lifespan.off import LifespanOff
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState

pytestmark = pytest.mark.anyio


class TolerantTransport(MockTransport):
    """In-memory transport that tolerates the close()/connection_lost() pairing
    that the real asyncio transport performs when a connection is torn down."""

    def close(self) -> None:
        self.closed = True


class BlockingApp:
    """ASGI app whose response only completes once `release` is resolved."""

    def __init__(self) -> None:
        self.calls = 0
        self._release: asyncio.Future[bool] | None = None

    @property
    def release(self) -> asyncio.Future[bool]:
        # Build the future explicitly on the running loop. A lazily created
        # asyncio.Event can bind its internal future to a different loop under
        # anyio's asyncio backend, which cancels the waiting app task.
        if self._release is None:
            self._release = asyncio.get_running_loop().create_future()
        return self._release

    async def __call__(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        self.calls += 1
        await self.release
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", b"2"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})


def make_protocol(
    app: Any,
    server_state: ServerState,
    *,
    limit_concurrency: int | None = None,
):
    config = Config(app=app, limit_concurrency=limit_concurrency)
    lifespan = LifespanOff(config)
    protocol = H11Protocol(
        config=config,
        server_state=server_state,
        app_state=lifespan.state,
        _loop=asyncio.get_running_loop(),
    )
    transport = TolerantTransport()
    transport.set_protocol(protocol)
    protocol.connection_made(transport)  # type: ignore[arg-type]
    return protocol


async def wait_until(predicate, *, checks: int = 1000):
    """Spin the event loop until `predicate` holds.

    The in-memory transport never blocks, so the protocol and its tasks make
    progress on every yield; a bounded number of iterations keeps the test
    deterministic without wall-clock sleeps.
    """
    for _ in range(checks):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition was not reached")


async def test_concurrency_limit_rejects_without_leaking_capacity():
    server_state = ServerState()
    app = BlockingApp()
    limit = 3

    # Drive two normal, in-flight requests. Each counts once through its
    # connection and once through its ASGI task, so both counters are at 2,
    # still below the limit of 3 and therefore served by the real application.
    first = make_protocol(app, server_state, limit_concurrency=limit)
    first.data_received(SIMPLE_GET_REQUEST)
    await wait_until(lambda: app.calls == 1)
    second = make_protocol(app, server_state, limit_concurrency=limit)
    second.data_received(SIMPLE_GET_REQUEST)
    await wait_until(lambda: app.calls == 2)

    assert len(server_state.connections) == 2
    assert len(server_state.tasks) == 2

    # Opening a third connection pushes the connection count to the limit, so
    # its request is rejected before the application runs. The built-in 503
    # handler answers instead and closes the rejected connection.
    third = make_protocol(app, server_state, limit_concurrency=limit)
    assert len(server_state.connections) == limit
    third.data_received(SIMPLE_GET_REQUEST)
    await wait_until(lambda: third.transport.is_closing())

    assert app.calls == 2
    assert b"HTTP/1.1 503 Service Unavailable" in third.transport.buffer
    assert b"connection: close" in third.transport.buffer
    assert b"Service Unavailable" in third.transport.buffer
    assert third.cycle.response_complete is True

    # The rejection runs its own short cycle. Its task is drained and, once the
    # client socket goes away, its connection is removed: nothing is left
    # holding a concurrency slot while the two accepted requests stay in flight.
    await wait_until(lambda: len(server_state.tasks) == 2)
    third.connection_lost(None)
    assert third not in server_state.connections
    assert len(server_state.connections) == 2

    # Complete the two accepted requests and let their tasks and sockets be
    # reclaimed.
    app.release.set_result(True)
    await wait_until(lambda: b"HTTP/1.1 200 OK" in first.transport.buffer)
    await wait_until(lambda: b"HTTP/1.1 200 OK" in second.transport.buffer)
    await wait_until(lambda: not server_state.tasks)
    first.connection_lost(None)
    second.connection_lost(None)
    assert not server_state.connections

    # A later normal connection is accepted and served by the real application,
    # proving the rejection left no capacity footprint behind.
    follow_up = make_protocol(app, server_state, limit_concurrency=limit)
    follow_up.data_received(SIMPLE_GET_REQUEST)
    await wait_until(lambda: follow_up.cycle.response_complete)

    assert app.calls == 3
    assert b"HTTP/1.1 200 OK" in follow_up.transport.buffer
    assert b"connection: close" not in follow_up.transport.buffer
    assert not follow_up.transport.is_closing()
    await wait_until(lambda: not server_state.tasks)
    follow_up.connection_lost(None)
    assert not server_state.connections
    assert not server_state.tasks


async def test_shutdown_while_request_in_flight_drains_and_reclaims():
    server_state = ServerState()
    app = BlockingApp()

    protocol = make_protocol(app, server_state)
    protocol.data_received(SIMPLE_GET_REQUEST)
    await wait_until(lambda: app.calls == 1)
    assert len(server_state.connections) == 1
    assert len(server_state.tasks) == 1
    assert not protocol.transport.is_closing()

    # Shutting down mid-request marks the active cycle as non-keep-alive but
    # must not interrupt the in-flight application response.
    protocol.shutdown()
    assert not protocol.transport.is_closing()
    assert protocol.cycle.keep_alive is False

    app.release.set_result(True)
    await wait_until(lambda: protocol.transport.is_closing())

    assert b"HTTP/1.1 200 OK" in protocol.transport.buffer
    assert protocol.cycle.response_complete is True
    await wait_until(lambda: not server_state.tasks)

    protocol.connection_lost(None)
    assert not server_state.connections
    assert not server_state.tasks


async def test_shutdown_while_idle_closes_without_creating_tasks():
    server_state = ServerState()
    app = BlockingApp()

    protocol = make_protocol(app, server_state)
    assert protocol in server_state.connections
    assert not server_state.tasks

    protocol.shutdown()

    assert app.calls == 0
    assert protocol.transport.is_closing()
    assert protocol.transport.buffer == b""
    assert not server_state.tasks

    protocol.connection_lost(None)
    assert not server_state.connections
    assert not server_state.tasks
