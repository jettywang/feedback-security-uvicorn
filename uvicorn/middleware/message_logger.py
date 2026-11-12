import logging
from typing import Any

from uvicorn._types import (
    ASGI3Application,
    ASGIReceiveCallable,
    ASGIReceiveEvent,
    ASGISendCallable,
    ASGISendEvent,
    WWWScope,
)
from uvicorn.logging import TRACE_LOG_LEVEL

PLACEHOLDER_FORMAT = {
    "body": "<{length} bytes>",
    "bytes": "<{length} bytes>",
    "text": "<{length} chars>",
    "headers": "<...>",
}


def message_with_placeholders(message: Any) -> Any:
    """
    Return an ASGI message, with any body-type content omitted and replaced
    with a placeholder.
    """
    new_message = message.copy()
    for attr in PLACEHOLDER_FORMAT.keys():
        if message.get(attr) is not None:
            content = message[attr]
            placeholder = PLACEHOLDER_FORMAT[attr].format(length=len(content))
            new_message[attr] = placeholder
    return new_message


def summarize_message(message: Any) -> dict[str, Any]:
    """
    Return the structured, payload-free view of an ASGI message.

    The summary is derived from ``message_with_placeholders`` so that the
    structured collector output and the human-readable trace output share
    the same retention rules: only the event type is kept, never the
    business payload.
    """
    redacted = message_with_placeholders(message)
    return {"asgi_event": redacted.get("type")}


class MessageLoggerMiddleware:
    def __init__(self, app: "ASGI3Application"):
        self.task_counter = 0
        self.app = app
        self.logger = logging.getLogger("uvicorn.asgi")

        def trace(message: Any, *args: Any, **kwargs: Any) -> None:
            self.logger.log(TRACE_LOG_LEVEL, message, *args, **kwargs)

        self.logger.trace = trace  # type: ignore

    async def __call__(
        self,
        scope: "WWWScope",
        receive: "ASGIReceiveCallable",
        send: "ASGISendCallable",
    ) -> None:
        self.task_counter += 1

        task_counter = self.task_counter
        client = scope.get("client")
        prefix = "%s:%d - ASGI" % (client[0], client[1]) if client else "ASGI"
        connection = "%s [%d]" % (prefix, task_counter)

        def log_extra(direction: str | None = None, message: Any = None) -> dict[str, Any]:
            fields: dict[str, Any] = {
                "asgi_connection": connection,
                "asgi_direction": direction,
            }
            if message is not None:
                fields.update(summarize_message(message))
            return fields

        async def inner_receive() -> "ASGIReceiveEvent":
            message = await receive()
            logged_message = message_with_placeholders(message)
            log_text = "%s [%d] Receive %s"
            self.logger.trace(  # type: ignore
                log_text, prefix, task_counter, logged_message, extra=log_extra("receive", message)
            )
            return message

        async def inner_send(message: "ASGISendEvent") -> None:
            logged_message = message_with_placeholders(message)
            log_text = "%s [%d] Send %s"
            self.logger.trace(  # type: ignore
                log_text, prefix, task_counter, logged_message, extra=log_extra("send", message)
            )
            await send(message)

        logged_scope = message_with_placeholders(scope)
        log_text = "%s [%d] Started scope=%s"
        self.logger.trace(log_text, prefix, task_counter, logged_scope, extra=log_extra(message=scope))  # type: ignore
        try:
            await self.app(scope, inner_receive, inner_send)
        except BaseException as exc:
            log_text = "%s [%d] Raised exception"
            self.logger.trace(log_text, prefix, task_counter, extra=log_extra())  # type: ignore
            raise exc from None
        else:
            log_text = "%s [%d] Completed"
            self.logger.trace(log_text, prefix, task_counter, extra=log_extra())  # type: ignore
