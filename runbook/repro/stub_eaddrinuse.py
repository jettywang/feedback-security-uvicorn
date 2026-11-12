"""替身：仅替换事件循环的 create_server，令其抛 EADDRINUSE。

用于在禁止 bind 的环境中，精确命中 uvicorn/server.py 中
`except OSError` 的端口占用分支，其余启动流程保持真实。
在允许绑定的机器上无需此文件，直接先占端口再起第二个进程即可。
"""
import asyncio
import errno

import uvicorn

_loop_cls = type(asyncio.new_event_loop())


def fake_create_server(self, *args, **kwargs):
    raise OSError(errno.EADDRINUSE, "Address already in use (stub)")


_loop_cls.create_server = fake_create_server

if __name__ == "__main__":
    config = uvicorn.Config("app_good:app", host="127.0.0.1", port=18080, log_level="info")
    uvicorn.Server(config).run()
