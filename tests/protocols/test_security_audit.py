from __future__ import annotations

import logging
from typing import Any

import pytest

from tests.protocols.test_http import get_connected_protocol
from tests.response import Response
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import LOGGING_CONFIG, Config
from uvicorn.logging import AccessFormatter
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.security_audit import (
    build_security_audit_record,
    normalize_auth_result,
    normalize_operation_id,
    set_security_audit,
)

HTTP_PROTOCOLS: list[type[Any]] = [H11Protocol]
try:
    from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

    HTTP_PROTOCOLS.append(HttpToolsProtocol)
except ModuleNotFoundError:  # pragma: no cover
    pass
try:
    from uvicorn.protocols.http.zttp_impl import ZttpProtocol

    HTTP_PROTOCOLS.append(ZttpProtocol)
except ModuleNotFoundError:  # pragma: no cover
    pass

pytestmark = pytest.mark.anyio

GET_REQUEST = b"\r\n".join([b"GET /audit HTTP/1.1", b"Host: example.org", b"X-Auth-Result: verified", b"", b""])


class AccessCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def access_capture() -> Any:
    logger = logging.getLogger("uvicorn.access")
    previous_handlers, previous_level, previous_propagate = logger.handlers[:], logger.level, logger.propagate
    capture = AccessCapture()
    logger.addHandler(capture)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        yield capture
    finally:
        logger.handlers = previous_handlers
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate


def audit_events(capture: AccessCapture) -> list[dict[str, Any]]:
    return [record.security_audit for record in capture.records if hasattr(record, "security_audit")]


@pytest.mark.parametrize(
    "value, expected",
    [
        ("anonymous", "anonymous"),
        ("verified", "verified"),
        ("denied", "denied"),
        ("superuser", None),
        ("", None),
        (True, None),
        (None, None),
        ("verified extra", None),
    ],
)
def test_auth_result_is_a_closed_vocabulary(value: Any, expected: str | None) -> None:
    assert normalize_auth_result(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("op-123", "op-123"),
        ("tenant/checkout", "tenant/checkout"),
        ("bad op", "bad_op"),
        ("line\nbreak", "line_break"),
        ("a" * 200, "a" * 128),
        ("", None),
        (123, None),
        (None, None),
    ],
)
def test_operation_id_is_bounded_and_log_safe(value: Any, expected: str | None) -> None:
    assert normalize_operation_id(value) == expected


def test_state_boundary_ignores_request_headers() -> None:
    scope: Scope = {  # type: ignore[typeddict-item]
        "type": "http",
        "method": "GET",
        "path": "/audit",
        "raw_path": b"/audit",
        "query_string": b"",
        "http_version": "1.1",
        "headers": [
            (b"x-auth-result", b"verified"),
            (b"x-operation-id", b"attacker-op"),
            (b"auth_result", b"denied"),
        ],
        "client": ("127.0.0.1", 8001),
        "state": {},
    }
    set_security_audit(scope, auth_result="anonymous")
    record = build_security_audit_record(scope, status=200)
    assert record["security_audit"] == {
        "event": "response",
        "auth_result": "anonymous",
        "operation_id": None,
        "client": "127.0.0.1:8001",
        "method": "GET",
        "path": "/audit",
        "status": 200,
    }
    assert record["security_event"] == "response"
    assert record["auth_result"] == "anonymous"
    assert b"attacker-op" not in repr(record).encode()


def test_scope_state_direct_fields_are_accepted() -> None:
    scope: Scope = {  # type: ignore[typeddict-item]
        "type": "http",
        "method": "POST",
        "path": "/audit",
        "raw_path": b"/audit",
        "query_string": b"",
        "http_version": "1.1",
        "headers": [],
        "client": None,
        "state": {"auth_result": "verified", "operation_id": "op-direct"},
    }
    record = build_security_audit_record(scope, status=201)
    assert record["auth_result"] == "verified"
    assert record["operation_id"] == "op-direct"
    assert record["security_event"] == "response"


def test_set_security_audit_does_not_require_existing_state() -> None:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/audit",
        "raw_path": b"/audit",
        "query_string": b"",
        "http_version": "1.1",
        "headers": [],
        "client": None,
    }
    set_security_audit(scope, auth_result="anonymous")  # type: ignore[arg-type]
    assert scope["state"]["uvicorn.security_audit"]["auth_result"] == "anonymous"


@pytest.mark.parametrize("http_protocol_cls", HTTP_PROTOCOLS, ids=lambda cls: cls.__name__)
async def test_disabled_by_default(http_protocol_cls: type[Any], access_capture: AccessCapture) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        set_security_audit(scope, auth_result="verified", operation_id="op-1")
        await Response("ok")(scope, receive, send)

    protocol = get_connected_protocol(app, http_protocol_cls, log_config=None)
    protocol.data_received(GET_REQUEST)
    await protocol.loop.run_one()

    assert b"HTTP/1.1 200 OK" in protocol.transport.buffer
    assert audit_events(access_capture) == []


@pytest.mark.parametrize("http_protocol_cls", HTTP_PROTOCOLS, ids=lambda cls: cls.__name__)
async def test_regular_response_emits_access_event(
    http_protocol_cls: type[Any], access_capture: AccessCapture
) -> None:
    observed: dict[str, Any] = {}

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        observed["state"] = scope["state"]
        observed["headers"] = list(scope["headers"])
        set_security_audit(scope, auth_result="verified", operation_id="op-42")
        await Response("ok")(scope, receive, send)

    protocol = get_connected_protocol(app, http_protocol_cls, log_config=None, security_audit=True)
    protocol.data_received(GET_REQUEST)
    await protocol.loop.run_one()

    assert b"HTTP/1.1 200 OK" in protocol.transport.buffer
    assert observed["state"]["uvicorn.security_audit"] == {
        "auth_result": "verified",
        "operation_id": "op-42",
    }
    # The forged request header is delivered to the application untouched but
    # is never consulted for the audit record.
    assert (b"x-auth-result", b"verified") in observed["headers"]
    events = audit_events(access_capture)
    assert events == [
        {
            "event": "response",
            "auth_result": "verified",
            "operation_id": "op-42",
            "client": "127.0.0.1:8001",
            "method": "GET",
            "path": "/audit",
            "status": 200,
        }
    ]
    records = [record for record in access_capture.records if hasattr(record, "security_audit")]
    assert len(records) == 1
    record = records[0]
    assert record.security_event == "response"
    assert record.auth_result == "verified"
    assert record.operation_id == "op-42"


@pytest.mark.parametrize("http_protocol_cls", HTTP_PROTOCOLS, ids=lambda cls: cls.__name__)
async def test_application_denial_is_distinguishable(
    http_protocol_cls: type[Any], access_capture: AccessCapture
) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        set_security_audit(scope, auth_result="denied", operation_id="op-denied")
        await Response("denied", status_code=403)(scope, receive, send)

    protocol = get_connected_protocol(app, http_protocol_cls, log_config=None, security_audit=True)
    protocol.data_received(GET_REQUEST)
    await protocol.loop.run_one()

    assert b"HTTP/1.1 403 Forbidden" in protocol.transport.buffer
    events = audit_events(access_capture)
    assert len(events) == 1
    assert events[0]["event"] == "denied"
    assert events[0]["auth_result"] == "denied"
    assert events[0]["status"] == 403


@pytest.mark.parametrize("http_protocol_cls", HTTP_PROTOCOLS, ids=lambda cls: cls.__name__)
async def test_application_exception_is_distinguishable(
    http_protocol_cls: type[Any], access_capture: AccessCapture, caplog: pytest.LogCaptureFixture
) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        set_security_audit(scope, auth_result="anonymous", operation_id="op-error")
        raise RuntimeError("boom")

    protocol = get_connected_protocol(app, http_protocol_cls, log_config=None, security_audit=True)
    protocol.data_received(GET_REQUEST)
    await protocol.loop.run_one()

    assert b"HTTP/1.1 500 Internal Server Error" in protocol.transport.buffer
    events = audit_events(access_capture)
    assert len(events) == 1
    assert events[0]["event"] == "error"
    assert events[0]["auth_result"] == "anonymous"
    assert events[0]["status"] == 500


@pytest.mark.parametrize("http_protocol_cls", HTTP_PROTOCOLS, ids=lambda cls: cls.__name__)
async def test_missing_context_is_safely_logged(
    http_protocol_cls: type[Any], access_capture: AccessCapture
) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await Response("ok")(scope, receive, send)

    protocol = get_connected_protocol(app, http_protocol_cls, log_config=None, security_audit=True)
    protocol.data_received(GET_REQUEST)
    await protocol.loop.run_one()

    events = audit_events(access_capture)
    assert events[0]["event"] == "response"
    assert events[0]["auth_result"] is None
    assert events[0]["operation_id"] is None


async def test_access_logging_still_works_without_audit(
    access_capture: AccessCapture, http_protocol_cls: type[Any]
) -> None:
    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        await Response("ok")(scope, receive, send)

    protocol = get_connected_protocol(app, http_protocol_cls, log_config=None)
    protocol.data_received(GET_REQUEST)
    await protocol.loop.run_one()

    messages = [record.getMessage() for record in access_capture.records]
    assert any("GET /audit HTTP/1.1" in message and " 200" in message for message in messages)
    assert audit_events(access_capture) == []


async def test_enabled_default_config_lines_include_fields(
    logging_config: dict[str, Any], access_capture: AccessCapture
) -> None:
    config = Config(
        app=Response("ok"),
        log_config=logging_config,
        security_audit=True,
        use_colors=False,
    )
    formatter = config.log_config["formatters"]["access"]
    formatter_instance = AccessFormatter(fmt=formatter["fmt"], use_colors=False)
    assert formatter["()"] == "uvicorn.logging.AccessFormatter"
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        "",
        0,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:8001", "GET", "/audit", "1.1", 403),
        None,
    )
    record.security_audit = {
        "event": "denied",
        "auth_result": "denied",
        "operation_id": "op-403",
    }
    # The audit fields are part of the message itself, so any formatter (default
    # or custom) exposes them.
    line = formatter_instance.format(record)
    assert line.endswith('security_event=denied auth_result=denied operation_id=op-403')
    assert "security_event=denied" in line
    assert "auth_result=denied" in line
    assert "operation_id=op-403" in line
    assert "security_event" not in formatter["fmt"]


def test_logging_config_default_is_not_mutated() -> None:
    assert "security_event" not in LOGGING_CONFIG["formatters"]["access"]["fmt"]
