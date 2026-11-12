async def app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.failed",
                            "message": "DB migration failed (stub)"})
                return
            if msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] != "http":
        return
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok\n"})
