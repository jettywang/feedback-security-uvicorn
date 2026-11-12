from __future__ import annotations

import logging
from collections.abc import Mapping, MutableMapping
from dataclasses import asdict, dataclass
from typing import Any

from uvicorn._types import WWWScope
from uvicorn.protocols.utils import get_client_addr, get_path_with_query_string

#: Preferred key under which the application registers the security context
#: for a request, as ``scope["state"]["uvicorn.security_audit"]``. The plain
#: ``security_audit`` key is also accepted. Values found in request headers,
#: the query string or the body are never used.
SECURITY_AUDIT_STATE_KEY = "uvicorn.security_audit"

#: The agreed classification vocabulary. A few unambiguous synonyms are
#: folded onto these canonical values; anything else is ignored, so an
#: application cannot publish free-form labels through the access record.
AUTH_RESULT_ALIASES = {
    "authenticated": "verified",
    "rejected": "denied",
    "unauthenticated": "anonymous",
}
AUTH_RESULTS = frozenset({"anonymous", "verified", "denied"})

_AUTH_RESULT_KEYS = ("auth_result", "auth_classification", "classification")
_OPERATION_ID_KEYS = ("operation_id", "operation")

MAX_OPERATION_ID_LENGTH = 128
MAX_AUDIT_PATH_LENGTH = 512

#: Normal response, explicit application denial, and an application that
#: exited before it could complete the response.
SECURITY_EVENT_RESPONSE = "response"
SECURITY_EVENT_DENIED = "denied"
SECURITY_EVENT_ERROR = "error"


def _state_context(scope: "WWWScope") -> Mapping[str, Any]:
    state = scope.get("state")
    if not isinstance(state, Mapping):
        return {}
    for key in (SECURITY_AUDIT_STATE_KEY, "security_audit"):
        context = state.get(key)
        if isinstance(context, Mapping):
            return context
    # Otherwise only the explicitly agreed fields are read from the state; any
    # other application state stays out of the audit record.
    if any(key in state for key in _AUTH_RESULT_KEYS + _OPERATION_ID_KEYS):
        return {key: state[key] for key in _AUTH_RESULT_KEYS + _OPERATION_ID_KEYS if key in state}
    return {}


def normalize_auth_result(value: Any) -> str | None:
    """Return one of the accepted classifications, else ``None``.

    The classification is deliberately closed: an application cannot smuggle
    an arbitrary label (or free-form business data) into the access record.
    """
    if not isinstance(value, str):
        return None
    value = AUTH_RESULT_ALIASES.get(value, value)
    if value in AUTH_RESULTS:
        return value
    return None


def normalize_operation_id(value: Any) -> str | None:
    """Return a bounded, log-safe operation identifier, else ``None``.

    Whitespace and non-printable characters are folded to ``_`` so an
    identifier cannot inject additional log lines or fields, and the result is
    truncated to :data:`MAX_OPERATION_ID_LENGTH`.
    """
    if not isinstance(value, str) or not value:
        return None
    safe = "".join(character if character.isprintable() and not character.isspace() else "_" for character in value)
    return safe[:MAX_OPERATION_ID_LENGTH]


def set_security_audit(
    scope: "WWWScope",
    *,
    auth_result: str,
    operation_id: str | None = None,
) -> None:
    """Register the security audit context for the current request.

    This is the explicit boundary for application middleware. Values are
    normalized here and later copied into the access record; request headers
    with the same names have no effect.
    """
    state = scope.get("state")
    if state is None:
        state = {}
        scope["state"] = state  # type: ignore[typeddict-item]
    if not isinstance(state, MutableMapping):  # pragma: no cover - ASGI contract
        return
    state[SECURITY_AUDIT_STATE_KEY] = {
        "auth_result": normalize_auth_result(auth_result),
        "operation_id": normalize_operation_id(operation_id),
    }


def _safe_path(scope: "WWWScope") -> str:
    path = scope.get("path") or ""
    if not isinstance(path, str):  # pragma: no cover - ASGI contract
        return ""
    path = "".join(character if character.isprintable() else "?" for character in path)
    return path[:MAX_AUDIT_PATH_LENGTH]


@dataclass(frozen=True)
class SecurityAuditEvent:
    """The bounded security projection of a finished HTTP request."""

    event: str
    auth_result: str | None
    operation_id: str | None
    client: str
    method: str
    path: str
    status: int | None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_security_audit_record(
    scope: "WWWScope",
    *,
    status: int | None,
    failed: bool = False,
) -> dict[str, Any]:
    """Build the ``extra`` mapping for a security-audited access record.

    ``failed`` is set when the application exited before it could finish the
    response, so abnormal terminations are distinguishable from ordinary
    responses and from an explicit application denial.
    """
    context = _state_context(scope)
    auth_result = normalize_auth_result(next((context[key] for key in _AUTH_RESULT_KEYS if key in context), None))
    operation_id = normalize_operation_id(next((context[key] for key in _OPERATION_ID_KEYS if key in context), None))

    if failed:
        event = SECURITY_EVENT_ERROR
    elif auth_result == "denied":
        event = SECURITY_EVENT_DENIED
    else:
        event = SECURITY_EVENT_RESPONSE

    payload = SecurityAuditEvent(
        event=event,
        auth_result=auth_result,
        operation_id=operation_id,
        client=get_client_addr(scope),
        method=scope.get("method") or "",
        path=_safe_path(scope),
        status=status,
    ).as_dict()
    return {
        "security_audit": payload,
        "security_event": event,
        "auth_result": auth_result,
        "operation_id": operation_id,
    }


def log_security_audit(
    access_logger: logging.Logger,
    scope: "WWWScope",
    *,
    status: int | None,
    failed: bool = False,
) -> None:
    """Emit the single record for a completed, security-audited request.

    The positional arguments stay identical to Uvicorn's normal access record
    so ``AccessFormatter`` keeps working; the security fields travel with
    ``extra`` and are available to custom formats. When this option is
    enabled it replaces the protocol's usual access record, so a request
    produces exactly one event.
    """
    record = build_security_audit_record(scope, status=status, failed=failed)
    try:
        path = get_path_with_query_string(scope)
    except (KeyError, TypeError):  # pragma: no cover - defensive for custom scopes
        path = record["security_audit"]["path"]
    access_logger.info(
        '%s - "%s %s HTTP/%s" %d',
        get_client_addr(scope),
        scope.get("method") or "",
        path,
        scope.get("http_version") or "",
        status if status is not None else 500,
        extra=record,
    )
