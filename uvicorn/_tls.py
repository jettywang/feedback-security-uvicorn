from __future__ import annotations

import ipaddress
import socket
from collections.abc import Sequence
from typing import Any, Protocol, TypeVar


class TLSConfigurationError(RuntimeError):
    """Raised when a listener's protocol does not match the TLS policy."""


class SocketLike(Protocol):
    """Structural type for the socket attributes the TLS policy relies on."""

    @property
    def family(self) -> int: ...

    def getsockname(self) -> Any: ...


_SocketT = TypeVar("_SocketT", bound=SocketLike)


def _describe_address(sock: SocketLike, name: object) -> str:
    if sock.family == socket.AF_INET6 and isinstance(name, tuple):
        host, port = name[0], name[1]
        return f"[{host}]:{port}"
    if isinstance(name, tuple):
        host, port = name[0], name[1]
        return f"{host}:{port}"
    return str(name)


def _is_local_address(sock: SocketLike, name: object) -> bool:
    if sock.family == socket.AF_UNIX:
        return True
    if not isinstance(name, tuple) or not name:
        return False
    host = name[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # `getsockname()` returned something `ipaddress` cannot parse
        # (e.g. a raw hostname); treat it conservatively as public.
        return False
    return address.is_loopback


def validate_listeners_tls(listeners: Sequence[_SocketT], *, ssl_enabled: bool) -> None:
    """Reject plaintext listeners bound to a non-local (public) address.

    Local loopback addresses and UNIX domain sockets are allowed to run
    without TLS; every other listener requires TLS to be configured.
    """
    if ssl_enabled:
        return

    for sock in listeners:
        name = sock.getsockname()
        if not _is_local_address(sock, name):
            address = _describe_address(sock, name)
            raise TLSConfigurationError(
                f"Refusing to start listener on {address}: TLS is required for non-local addresses, "
                "but no SSL configuration was provided. Bind to a loopback address or configure "
                "`ssl_certfile`/`ssl_context_factory`."
            )
