from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ShutdownPhase(StrEnum):
    """Phases of the server graceful shutdown sequence.

    The phases are emitted in declaration order.
    """

    SHUTDOWN_STARTED = "shutdown.started"
    WAITING_FOR_CONNECTIONS = "shutdown.waiting_for_connections"
    WAITING_FOR_TASKS = "shutdown.waiting_for_tasks"
    GRACEFUL_PERIOD_COMPLETED = "shutdown.graceful_period_completed"
    GRACEFUL_PERIOD_EXCEEDED = "shutdown.graceful_period_exceeded"
    TASKS_CANCELLED = "shutdown.tasks_cancelled"
    LIFESPAN_SHUTDOWN_STARTED = "shutdown.lifespan_shutdown_started"
    LIFESPAN_SHUTDOWN_COMPLETED = "shutdown.lifespan_shutdown_completed"
    LIFESPAN_SHUTDOWN_FAILED = "shutdown.lifespan_shutdown_failed"
    SHUTDOWN_COMPLETED = "shutdown.completed"


@dataclass(frozen=True, slots=True)
class ShutdownEvent:
    """A read-only notification about a graceful shutdown phase.

    Only phase names and aggregate counters are carried. No request, connection
    or task object (and therefore no request content) is ever included.
    """

    phase: ShutdownPhase
    pending_tasks: int
    completed_tasks: int
    cancelled_tasks: int
