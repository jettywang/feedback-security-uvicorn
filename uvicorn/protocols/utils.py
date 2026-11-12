from __future__ import annotations

import asyncio
import socket
from typing import TypedDict, cast

from uvicorn._types import WWWScope

#: Scope extension key under which Uvicorn records the direct transport peer
#: of the connection, as ``scope["extensions"]["uvicorn.direct_client"]["client"]``.
#: Unlike ``scope["client"]`` this is never rewritten by proxy-header
#: processing, so audit tooling can always recover the address of the party
#: that actually opened the connection.
DIRECT_CLIENT_EXTENSION = "uvicorn.direct_client"


class ClientDisconnected(OSError): ...


def get_remote_addr(transport: asyncio.Transport) -> tuple[str, int] | None:
    socket_info: socket.socket | None = transport.get_extra_info("socket")
    if socket_info is not None:
        try:
            info = socket_info.getpeername()
            return (str(info[0]), int(info[1])) if isinstance(info, tuple) else None
        except OSError:  # pragma: no cover
            # This case appears to inconsistently occur with uvloop
            # bound to a unix domain socket.
            return None

    info = transport.get_extra_info("peername")
    if info is not None and isinstance(info, list | tuple) and len(info) == 2:
        return (str(info[0]), int(info[1]))
    return None


def get_local_addr(transport: asyncio.Transport) -> tuple[str, int | None] | None:
    socket_info: socket.socket | None = transport.get_extra_info("socket")
    if socket_info is not None:
        info = socket_info.getsockname()
        if isinstance(info, tuple):
            return (str(info[0]), int(info[1]))
        if isinstance(info, str):
            return (info, None)
        return None
    info = transport.get_extra_info("sockname")
    if info is not None and isinstance(info, list | tuple) and len(info) == 2:
        return (str(info[0]), int(info[1]))
    if isinstance(info, str):
        return (info, None)
    return None


def is_ssl(transport: asyncio.Transport) -> bool:
    return bool(transport.get_extra_info("sslcontext"))


def get_client_addr(scope: WWWScope) -> str:
    client = scope.get("client")
    if not client:
        return ""
    return "%s:%d" % client


def get_direct_client_addr(scope: WWWScope) -> str:
    """Return the direct transport peer of the connection.

    Unlike `get_client_addr`, this reflects the party that opened the
    connection and is not affected by `ProxyHeadersMiddleware`. Falls back
    to ``scope["client"]`` for scopes not created by Uvicorn's protocols.
    """
    extensions = scope.get("extensions") or {}
    extension = extensions.get(DIRECT_CLIENT_EXTENSION) or {}
    client = cast("tuple[str, int] | None", extension.get("client")) or scope.get("client")
    if not client:
        return ""
    return "%s:%d" % client


class ClientSecuritySummary(TypedDict):
    #: Address of the peer that opened the connection.
    direct: str
    #: Address exposed to the application, after trusted proxy-header processing.
    effective: str
    #: Whether the two differ, i.e. the effective address was resolved from proxy headers.
    proxied: bool


def get_client_security_summary(scope: WWWScope) -> ClientSecuritySummary:
    """Snapshot of both client addresses in a scope, for audit logging.

    ``direct`` is the transport peer that opened the connection; ``effective``
    is the address the application sees in ``scope["client"]``. When a trusted
    proxy is fronting the server these differ and ``proxied`` is true, which
    tells audit trails whether an access-log client address is the connecting
    party or an address resolved from proxy headers.
    """
    direct = get_direct_client_addr(scope)
    effective = get_client_addr(scope)
    return {"direct": direct, "effective": effective, "proxied": direct != effective}


def get_path_with_query_string(scope: WWWScope) -> str:
    path_with_query_string = scope["raw_path"].decode("latin1")
    if scope["query_string"]:
        path_with_query_string = "{}?{}".format(path_with_query_string, scope["query_string"].decode("ascii"))
    return path_with_query_string.replace('"', "%22")
