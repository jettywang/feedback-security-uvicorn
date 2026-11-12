from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

from uvicorn._types import WebSocketScope
from uvicorn.protocols.utils import get_client_addr, get_path_with_query_string

AUDIT_LOGGER_NAME = "uvicorn.websocket.audit"

# Close codes with no close frame, or whose meaning is "the transport ended
# without a closing handshake". Everything else is an orderly close category.
ABNORMAL_CLOSE_CODES = frozenset({1005, 1006})


class AuditPhase(str, Enum):
    """Stable lifecycle stage at which the connection ended."""

    HANDSHAKE = "handshake"
    SESSION = "session"


class AuditStatus(str, Enum):
    """Coarse, application-independent termination categories.

    Business close reasons and exact close codes are deliberately not part of
    this vocabulary, so centralized logs cannot retain application diagnostics.
    """

    REJECTED = "rejected"
    CLOSED = "closed"
    ABNORMAL = "abnormal"


@dataclass(frozen=True)
class WebSocketAuditEvent:
    """The security projection of a terminated WebSocket connection."""

    phase: AuditPhase
    status: AuditStatus
    client: str
    path: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "status": self.status.value,
            "client": self.client,
            "path": self.path,
        }


def classify_close_code(code: int | None) -> AuditStatus:
    """Project a WebSocket close code onto a stable status category.

    The exact code is only used to distinguish an orderly close from an
    abnormal termination; it is never forwarded to the audit sink itself.
    """
    if code is None or code in ABNORMAL_CLOSE_CODES:
        return AuditStatus.ABNORMAL
    return AuditStatus.CLOSED


class WebSocketAuditMixin:
    """Shared, opt-in audit projection for the WebSocket protocol backends.

    Enable it with the `ws_audit` configuration option. The mixin records a
    single stable event per connection and never logs a close reason string.
    """

    config: Any
    scope: WebSocketScope

    def __init__(self) -> None:
        self._ws_audit_emitted = False
        self._ws_accepted = False

    @property
    def ws_audit_enabled(self) -> bool:
        return bool(getattr(self.config, "ws_audit", False))

    def audit_handshake_rejected(self) -> None:
        self._emit_audit(AuditPhase.HANDSHAKE, AuditStatus.REJECTED)

    def audit_closed(self, phase: AuditPhase, status: AuditStatus) -> None:
        self._emit_audit(phase, status)

    def audit_connection_lost(self) -> None:
        phase = AuditPhase.SESSION if self._ws_accepted else AuditPhase.HANDSHAKE
        self._emit_audit(phase, AuditStatus.ABNORMAL)

    def _emit_audit(self, phase: AuditPhase, status: AuditStatus) -> None:
        if not self.ws_audit_enabled or self._ws_audit_emitted:
            return
        self._ws_audit_emitted = True
        scope = getattr(self, "scope", None)
        if scope is None:
            client = ""
            path = ""
        else:
            client = get_client_addr(scope)
            path = get_path_with_query_string(scope)
        event = WebSocketAuditEvent(phase=phase, status=status, client=client, path=path)
        payload = event.as_dict()
        logging.getLogger(AUDIT_LOGGER_NAME).info(
            "WebSocket connection ended: phase=%s status=%s",
            payload["phase"],
            payload["status"],
            extra={"websocket_audit": payload},
        )
