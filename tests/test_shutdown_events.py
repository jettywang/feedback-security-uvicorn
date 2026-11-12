from __future__ import annotations

import asyncio
from dataclasses import FrozenInstanceError
from typing import TYPE_CHECKING, cast

import pytest

from uvicorn.config import Config
from uvicorn.server import Server
from uvicorn.shutdown import ShutdownEvent, ShutdownPhase

if TYPE_CHECKING:
    from uvicorn.lifespan.on import LifespanOn
    from uvicorn.server import Protocols

pytestmark = pytest.mark.anyio


class FakeLifespan:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.should_exit = False
        self.shutdown_called = False

    async def shutdown(self) -> None:
        self.shutdown_called = True
        if self.fail:
            self.should_exit = True


class FakeConnection:
    def __init__(self) -> None:
        self.shutdown_called = False

    def shutdown(self) -> None:
        self.shutdown_called = True


class FakeAsyncioServer:
    def __init__(self) -> None:
        self.closed = False
        self.wait_called = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.wait_called = True


def build_server(
    *, timeout: int | None, lifespan_fail: bool = False, force_exit: bool = False, with_connection: bool = False
) -> Server:
    config = Config(app=dummy_app, timeout_graceful_shutdown=timeout)
    server = Server(config=config)
    server.servers = [FakeAsyncioServer()]  # type: ignore[list-item]
    if with_connection:
        server.server_state.connections.add(cast("Protocols", FakeConnection()))
    server.lifespan = cast("LifespanOn", FakeLifespan(fail=lifespan_fail))
    server.force_exit = force_exit
    return server


async def dummy_app(scope, receive, send):  # pragma: no cover
    pass


def register(server: Server, task: asyncio.Task[None]) -> None:
    task.add_done_callback(server.server_state.tasks.discard)
    server.server_state.tasks.add(task)


async def wait_for(event: asyncio.Event) -> None:
    await event.wait()


async def collect(server: Server) -> list[ShutdownEvent]:
    return [event async for event in server.subscribe_shutdown_events()]


def phases(events: list[ShutdownEvent]) -> list[ShutdownPhase]:
    return [event.phase for event in events]


async def test_events_when_tasks_complete_within_budget():
    """One immediate task and one waiting task both finish inside the budget."""
    server = build_server(timeout=None)

    release_quick = asyncio.Event()
    release_slow = asyncio.Event()
    quick = asyncio.create_task(wait_for(release_quick))
    slow = asyncio.create_task(wait_for(release_slow))
    register(server, quick)
    register(server, slow)

    collected: list[ShutdownEvent] = []
    recorder_ready = asyncio.Event()

    async def record() -> None:
        stream = server.subscribe_shutdown_events()
        recorder_ready.set()
        async for event in stream:
            collected.append(event)

    recorder = asyncio.create_task(record())
    await recorder_ready.wait()

    async def release_tasks() -> None:
        # Keep both tasks pending until the waiting phase is announced, so the
        # waiting event observes two pending tasks. The quick one is released
        # immediately, the slow one a moment later; both finish in the budget.
        while not any(event.phase is ShutdownPhase.WAITING_FOR_TASKS for event in collected):
            await asyncio.sleep(0.01)
        release_quick.set()
        await asyncio.sleep(0.02)
        release_slow.set()

    releaser = asyncio.create_task(release_tasks())
    await server.shutdown()
    await releaser
    await recorder
    events = collected

    assert phases(events) == [
        ShutdownPhase.SHUTDOWN_STARTED,
        ShutdownPhase.WAITING_FOR_TASKS,
        ShutdownPhase.GRACEFUL_PERIOD_COMPLETED,
        ShutdownPhase.LIFESPAN_SHUTDOWN_STARTED,
        ShutdownPhase.LIFESPAN_SHUTDOWN_COMPLETED,
        ShutdownPhase.SHUTDOWN_COMPLETED,
    ]

    started, waiting, grace_ok, lifespan_start, lifespan_ok, finished = events
    assert started.pending_tasks == 2
    assert waiting.pending_tasks == 2
    assert grace_ok.pending_tasks == 0
    assert grace_ok.completed_tasks == 2
    assert grace_ok.cancelled_tasks == 0
    assert lifespan_start.completed_tasks == 2
    assert lifespan_ok.completed_tasks == 2
    assert finished.completed_tasks == 2
    assert finished.cancelled_tasks == 0
    assert finished.pending_tasks == 0

    # Final state: both tasks done and removed, no cancellation recorded.
    assert quick.done() and not quick.cancelled()
    assert slow.done() and not slow.cancelled()
    assert server.server_state.tasks == set()
    assert server.servers[0].closed and server.servers[0].wait_called
    assert server.lifespan.shutdown_called


async def test_events_distinguish_cancellation_from_lifespan_failure():
    """Budget exhausted: one task finishes, one is cancelled, then lifespan fails."""
    server = build_server(timeout=1, lifespan_fail=True)

    release_quick = asyncio.Event()
    never_release = asyncio.Event()
    quick = asyncio.create_task(wait_for(release_quick))
    hanging = asyncio.create_task(wait_for(never_release))
    register(server, quick)
    register(server, hanging)

    collected: list[ShutdownEvent] = []
    recorder_ready = asyncio.Event()

    async def record() -> None:
        stream = server.subscribe_shutdown_events()
        recorder_ready.set()
        async for event in stream:
            collected.append(event)

    recorder = asyncio.create_task(record())
    await recorder_ready.wait()

    async def release_after_waiting_phase() -> None:
        # Do not release until the server has announced the waiting phase,
        # otherwise the short task drains before the event is emitted.
        while not any(event.phase is ShutdownPhase.WAITING_FOR_TASKS for event in collected):
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        release_quick.set()

    releaser = asyncio.create_task(release_after_waiting_phase())
    await server.shutdown()
    await releaser
    await recorder
    events = collected

    assert phases(events) == [
        ShutdownPhase.SHUTDOWN_STARTED,
        ShutdownPhase.WAITING_FOR_TASKS,
        ShutdownPhase.GRACEFUL_PERIOD_EXCEEDED,
        ShutdownPhase.TASKS_CANCELLED,
        ShutdownPhase.LIFESPAN_SHUTDOWN_STARTED,
        ShutdownPhase.LIFESPAN_SHUTDOWN_FAILED,
        ShutdownPhase.SHUTDOWN_COMPLETED,
    ]

    started, waiting, exceeded, cancelled_event, lifespan_start, failed, finished = events
    assert started.pending_tasks == 2
    assert waiting.pending_tasks == 2
    # The short task drained before the deadline; the hanging one did not.
    assert exceeded.pending_tasks == 1
    assert exceeded.completed_tasks == 1
    assert exceeded.cancelled_tasks == 1
    assert cancelled_event.pending_tasks == 1
    assert cancelled_event.cancelled_tasks == 1
    assert cancelled_event.completed_tasks == 1
    # Application shutdown failure is a separate phase from task cancellation.
    assert failed.phase is ShutdownPhase.LIFESPAN_SHUTDOWN_FAILED
    assert failed.cancelled_tasks == 1
    assert finished.cancelled_tasks == 1
    assert finished.completed_tasks == 1

    # Let the cancelled task settle and verify final state.
    with pytest.raises(asyncio.CancelledError):
        await hanging
    await asyncio.sleep(0)
    assert quick.done() and not quick.cancelled()
    assert hanging.cancelled()
    assert server.server_state.tasks == set()
    assert server.lifespan.should_exit
    assert server.lifespan.shutdown_called


async def test_events_are_read_only_and_carry_no_request_data():
    server = build_server(timeout=None)
    drain = asyncio.create_task(collect(server))
    await asyncio.sleep(0)

    await server.shutdown()
    events = await drain

    assert events
    for event in events:
        assert isinstance(event, ShutdownEvent)
        with pytest.raises(FrozenInstanceError):
            event.phase = ShutdownPhase.SHUTDOWN_COMPLETED
        with pytest.raises(FrozenInstanceError):
            event.pending_tasks = 3
        assert set(event.__dataclass_fields__) == {
            "phase",
            "pending_tasks",
            "completed_tasks",
            "cancelled_tasks",
        }


async def test_shutdown_without_subscribers_still_runs():
    server = build_server(timeout=None)
    release = asyncio.Event()
    task = asyncio.create_task(wait_for(release))
    register(server, task)

    async def complete() -> None:
        await asyncio.sleep(0.02)
        release.set()

    completer = asyncio.create_task(complete())
    await server.shutdown()
    await completer

    assert task.done() and not task.cancelled()
    assert server.server_state.tasks == set()
    assert server.lifespan.shutdown_called


async def test_waiting_for_connections_phase_is_emitted():
    """A lingering connection produces the waiting-for-connections phase, then drains."""
    server = build_server(timeout=None, with_connection=True)
    connection = next(iter(server.server_state.connections))

    collected: list[ShutdownEvent] = []
    recorder_ready = asyncio.Event()

    async def record() -> None:
        stream = server.subscribe_shutdown_events()
        recorder_ready.set()
        async for event in stream:
            collected.append(event)

    recorder = asyncio.create_task(record())
    await recorder_ready.wait()

    async def drop_connection() -> None:
        while not any(event.phase is ShutdownPhase.WAITING_FOR_CONNECTIONS for event in collected):
            await asyncio.sleep(0.01)
        server.server_state.connections.discard(connection)

    dropper = asyncio.create_task(drop_connection())
    await server.shutdown()
    await dropper
    await recorder

    assert phases(collected) == [
        ShutdownPhase.SHUTDOWN_STARTED,
        ShutdownPhase.WAITING_FOR_CONNECTIONS,
        ShutdownPhase.GRACEFUL_PERIOD_COMPLETED,
        ShutdownPhase.LIFESPAN_SHUTDOWN_STARTED,
        ShutdownPhase.LIFESPAN_SHUTDOWN_COMPLETED,
        ShutdownPhase.SHUTDOWN_COMPLETED,
    ]
    assert connection.shutdown_called


async def test_force_exit_skips_waiting_and_lifespan_phases():
    server = build_server(timeout=None, force_exit=True, with_connection=True)

    never_release = asyncio.Event()
    hanging = asyncio.create_task(wait_for(never_release))
    register(server, hanging)

    drain = asyncio.create_task(collect(server))
    await asyncio.sleep(0)

    await server.shutdown()
    events = await drain
    hanging.cancel()
    with pytest.raises(asyncio.CancelledError):
        await hanging

    assert phases(events) == [
        ShutdownPhase.SHUTDOWN_STARTED,
        ShutdownPhase.GRACEFUL_PERIOD_COMPLETED,
        ShutdownPhase.SHUTDOWN_COMPLETED,
    ]
    assert not server.lifespan.shutdown_called
    assert server.server_state.tasks == set()


async def test_multiple_subscribers_receive_identical_stream():
    server = build_server(timeout=None)
    first = asyncio.create_task(collect(server))
    second = asyncio.create_task(collect(server))
    await asyncio.sleep(0)

    await server.shutdown()

    assert await first == await second
