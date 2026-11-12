#!/usr/bin/env bash
# Uvicorn 启动三阶段失败本地复现（证书 / ASGI lifespan / 端口占用）。
# 仅绑 127.0.0.1，证书即时生成到临时目录，不使用生产证书、不监听公网。
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPRO="$HERE/repro"
LAB="$(mktemp -d "${TMPDIR:-/tmp}/uviclab.XXXXXX")"
PY="${PYTHON:-python3}"
PORT="${PORT:-18080}"
cp "$REPRO"/*.py "$LAB"/
cd "$LAB"

banner() { printf '\n================ %s ================\n' "$1"; }
run() { echo "\$ $*"; "$@"; echo "[exit=$?]"; }

# --- 生成测试证书：正常件 / 损坏件 / 不匹配件 ---
openssl req -x509 -newkey rsa:2048 -nodes -keyout good.key -out good.crt -days 1 \
  -subj "/CN=localhost" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.crt -days 1 \
  -subj "/CN=other" >/dev/null 2>&1
printf 'not-a-certificate\n' > bad.crt
echo "lab dir: $LAB"

banner "阶段1A 证书损坏 -> 期望 exit=1, 纯 Traceback, 无 Started server process"
run "$PY" -m uvicorn app_good:app --host 127.0.0.1 --port "$PORT" \
  --ssl-certfile bad.crt --ssl-keyfile good.key

banner "阶段1B 证书/私钥不匹配 -> 期望 exit=1, KEY_VALUES_MISMATCH"
run "$PY" -m uvicorn app_good:app --host 127.0.0.1 --port "$PORT" \
  --ssl-certfile good.crt --ssl-keyfile other.key

banner "阶段1C 应用模块顶层异常 -> 期望 exit=1, RuntimeError Traceback"
run "$PY" -m uvicorn app_import_boom:app --host 127.0.0.1 --port "$PORT"

banner "阶段2 lifespan 硬失败 (--lifespan on) -> 期望 exit=3, Application startup failed"
run "$PY" -m uvicorn app_lifespan_fail:app --lifespan on --host 127.0.0.1 --port "$PORT"

banner "阶段3 端口占用 EADDRINUSE -> 期望 exit=3, bind 错误出现在 startup complete 之后"
# 优先真实占用端口；若环境禁止 bind，回退到 stub（命中同一 except OSError 分支）。
if "$PY" - <<PY 2>/dev/null
import socket; s=socket.socket(); s.bind(("127.0.0.1", $PORT)); s.listen(1)
PY
then
  "$PY" - <<PY &
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1", $PORT)); s.listen(8); time.sleep(15)
PY
  HOLDER=$!
  sleep 1
  run "$PY" -m uvicorn app_good:app --host 127.0.0.1 --port "$PORT"
  kill "$HOLDER" 2>/dev/null
else
  echo "(环境禁止 bind，回退 stub 抛 EADDRINUSE)"
  run "$PY" stub_eaddrinuse.py
fi

echo
echo "判据回顾：出现 'Uvicorn running on ...' 才代表已监听并接收连接；"
echo "证书问题停在第一条 INFO 之前(exit 1)，lifespan 停在 startup(exit 3)，端口问题在 complete 之后(exit 3)。"
