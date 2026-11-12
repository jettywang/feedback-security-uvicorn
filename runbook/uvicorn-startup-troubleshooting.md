# Uvicorn 启动失败三阶段排查说明（证书 / ASGI / 端口）

适用版本：本仓库 `uvicorn` 0.54.0（结论依据随附源码行号；其它 0.x 版本启动顺序一致，仅日志措辞略有差异）。
所有验证均在 `127.0.0.1` 本地完成，证书为本机即时生成的自签测试件，不使用生产证书、不监听公网。

---

## 1. 先记住真实启动顺序

单 worker、走 `uvicorn ...` / `Server.run()` 时，`Server._serve()` → `Server.startup()` 的实际顺序如下（见 `uvicorn/server.py:92`、`uvicorn/config.py:438`）：

| 步 | 动作 | 发生位置 | 成功时的日志锚点 |
|---|------|----------|------------------|
| ① | `config.load()`：构造 `SSLContext`（`load_cert_chain`），随后 `load_app()` 导入 ASGI 应用 | `config.py:482` / `config.py:510` | 本步**不打印任何成功日志** |
| ② | 打印进程已起 | `server.py:103` | `Started server process [<pid>]` |
| ③ | Lifespan 启动（向应用发 `lifespan.startup`） | `server.py:116` | `Waiting for application startup.` → `Application startup complete.` |
| ④ | 创建并绑定 socket（`loop.create_server(host, port, ssl=...)`） | `server.py:182` | 绑定成功后 `server.py:199` 调 `_log_started_message` |
| ⑤ | 置 `self.started = True`，进入 `main_loop` 接收连接 | `server.py:205`、`server.py:242` | `Uvicorn running on http(s)://host:port (Press CTRL+C to quit)` |

三个易混故障分别落在不同步：

- 证书加载失败 → **步①**（最早，在任何 `INFO` 日志之前）
- ASGI 启动失败 → 又分两处：**应用导入失败在步①**；**lifespan 失败在步③**
- 端口占用 → **步④**（最晚，lifespan 已成功之后）

关键事实：**socket 在第④步才创建并监听**。因此①③阶段的失败，进程根本没有监听端口。

---

## 2. 三种失败的实测特征

下表全部来自本地真实子进程复现（命令见第 6 节与 `runbook/reproduce.sh`）。

### 阶段一：证书加载失败（步①）

触发方式：`--ssl-certfile` 指向损坏 PEM，或证书与私钥不匹配。

```
Traceback (most recent call last):
  ...
  File ".../uvicorn/config.py", line 131, in create_ssl_context
    ctx.load_cert_chain(certfile, keyfile, get_password)
ssl.SSLError: [SSL] PEM lib (_ssl.c:3855)          # 损坏证书
ssl.SSLError: [X509: KEY_VALUES_MISMATCH] ...      # 证书/私钥不匹配
```

- 退出码：**1**（未捕获异常的 Python 默认码）。原因是 `create_ssl_context` 在 `config.load()` 内**没有 try/except 包裹**（`config.py:480-491`），异常一路冒泡出 `server.run()`，`main.py:650` 的退出码 3 兜底逻辑根本走不到。
- 日志特征：**只有原始 Traceback，没有 `Started server process`，更没有 `Waiting for application startup`**。
- 是否接收连接：**否**。socket 尚未创建。
- 同类邻居：应用导入失败（`Error loading ASGI app ...`）也在步①，但它被 `config.load_app()` 捕获并 `sys.exit(3)`（`config.py:430-436`），是**干净的一行 ERROR + 退出码 3，无 Traceback**；若导入的模块在顶层直接 `raise`，则同样以未捕获异常收尾、**退出码 1 + Traceback**。

### 阶段二：ASGI / lifespan 启动失败（步③）

触发方式：应用在 lifespan 中回复 `lifespan.startup.failed`，或 lifespan 协程抛异常。

显式 `--lifespan on` 时的实测输出：

```
INFO:     Started server process [<pid>]
INFO:     Waiting for application startup.
ERROR:    Exception in 'lifespan' protocol
Traceback (most recent call last):
  ...
RuntimeError: boom during lifespan (stub)
ERROR:    Application startup failed. Exiting.
```

- 退出码：**3**（`STARTUP_FAILURE`，`config.py:81`；由 `server.py:117-118` 的 `sys.exit(STARTUP_FAILURE)` 触发）。
- 日志特征：**有 `Started server process`、有 `Waiting for application startup`，但没有 `Application startup complete.`，以 `Application startup failed. Exiting.` 收尾**。
- 是否接收连接：**否**。失败发生在 `startup()` 绑定 socket 之前（`server.py:116` 早于 `server.py:182`）。

> ⚠️ 易踩的坑——默认 `lifespan=auto`。默认模式下，若 lifespan 协程抛异常，uvicorn 会判定“应用不支持 lifespan”并**降级继续**，打印
> `ASGI 'lifespan' protocol appears unsupported.` 然后照常 `Application startup complete.` 并继续去绑端口。
> 也就是说：**默认 auto 模式下，lifespan 内的未捕获异常不会让启动失败**。要让它成为硬失败，必须显式 `--lifespan on`（或 `lifespan="on"`）。排查“应用初始化没生效却起来了”的问题时优先检查这一项。

### 阶段三：端口占用 / 绑定失败（步④）

触发方式：端口已被占用，系统返回 `EADDRINUSE`（macOS/Linux 为 errno 48/98）。受沙箱限制无法真占端口，这里用替身让 `loop.create_server` 抛 `EADDRINUSE`，命中的是与真实占用完全相同的 `except OSError` 分支（`server.py:189-192`）：

```
INFO:     Started server process [<pid>]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
ERROR:    [Errno 48] Address already in use
INFO:     Waiting for application shutdown.
INFO:     Application shutdown complete.
```

- 退出码：**3**（`server.py:192` 的 `sys.exit(STARTUP_FAILURE)`）。
- 日志特征：**`Application startup complete.` 已经出现**，随后才是 `error while attempting to bind on address ('host', port)`，并触发一次 lifespan shutdown。
- 是否接收连接：**这个新进程没有监听任何端口，不接收连接**。但要注意：旧的占用进程仍在正常监听并应答——健康检查/`curl` 此刻打到的是**旧实例**，这正是“日志报错但流量好像正常”的根因。
- 同分支其它 `OSError`：权限不足（Linux 绑 <1024 端口、`CAP_NET_BIND_SERVICE` 缺失）、地址不可用（绑了本机不存在的 IP）等，日志结构与退出码完全相同，仅 errno/文案不同。本机沙箱即实测到 `[Errno 1] operation not permitted`，同样落在该分支、退出码 3。

---

## 3. 可靠判据：用日志锚点 + 退出码二段定位

按下面顺序判，不要只看“有没有报错”。

**第一判据——最后一条 `INFO` 锚点走到哪一步：**

1. 连 `Started server process` 都没有，只有 `Traceback` / `ssl.SSLError`
   → **证书（或步①的模块顶层异常）**。失败在最早的 `config.load()`。
2. 有 `Started server process` + `Waiting for application startup`，停在 `Application startup failed. Exiting.`
   → **ASGI lifespan 失败**（确认是否已设 `--lifespan on`）。
3. 已经出现 `Application startup complete.`，随后才报 `error while attempting to bind on address`
   → **端口/绑定阶段**。
4. 出现 `Uvicorn running on ...`
   → 绑定与监听全部成功，服务**已开始接收连接**。这是“真的起来了”的唯一可靠信号。

**第二判据——进程退出码（区分同为早期失败的两类）：**

- 退出码 `1` + 原始 Traceback：未捕获异常，典型是 `ssl.SSLError` 或应用模块顶层 `raise`。
- 退出码 `3`（`STARTUP_FAILURE`）：uvicorn 主动识别的启动失败——lifespan 失败、绑定 `OSError`、`import_from_string` 导入错误、工厂错误等。
- 退出码 `0`：正常运行后被优雅停止。

> 最稳的单一信号是 **`Uvicorn running on <scheme>://<host>:<port>` 这条日志**：它由 `_log_started_message` 在 `create_server` 成功后才打印（`server.py:199`、`server.py:232`），出现即代表 socket 已监听、`self.started=True`。反之，**没看到这条 = 一定没有在接收连接**，无论前面打印了多少 `INFO`。注意 `Started server process` 只代表进程与配置就绪，**不代表能接流量**，别拿它当就绪信号。

---

## 4. 各失败下“有没有开始接收连接”汇总

| 故障 | 失败步 | socket 是否已监听 | 新进程接收连接？ | 退出码 | 可能仍应答的是谁 |
|------|--------|------------------|------------------|--------|------------------|
| 证书加载失败 | ① | 否 | 否 | 1 | 无（本进程从未监听） |
| 应用导入失败（捕获） | ① | 否 | 否 | 3 | 无 |
| 模块顶层异常 | ① | 否 | 否 | 1 | 无 |
| lifespan 失败（`lifespan on`） | ③ | 否 | 否 | 3 | 无 |
| lifespan 异常（默认 `auto`） | ③降级 | 继续走到④ | 会继续启动（非硬失败） | 0/3* | 本进程会正常监听 |
| 端口占用 `EADDRINUSE` | ④ | 否（新进程绑定失败） | 新进程否 | 3 | **旧占用进程仍在应答** |

\* auto 降级后若后续 bind 也失败则为 3，bind 成功则正常运行为 0。

运维含义：排查“连不上”时，先确认报错的是**新进程**还是**旧进程**；端口占用场景下流量可能仍被旧实例承接，需要用 `lsof -nP -iTCP:<port> -sTCP:LISTEN`（Linux 也可用 `ss -ltnp` / `fuser <port>/tcp`）核对监听者 PID，而不是只看健康检查返回。

---

## 5. 哪些证书设置适合写进日志

原则：**只记录“定位配置问题所必需”的非秘密、非完整 PEM 信息**；私钥与口令任何级别都不落日志。

适合记录（DEBUG/INFO，启动时打一次即可）：

- 是否启用 TLS：布尔值（`config.ssl is not None`），以及最终 scheme 是 `http` 还是 `https`。
- 证书/私钥/CA 的**文件路径**（`ssl_certfile`、`ssl_keyfile`、`ssl_ca_certs` 的路径字符串，便于发现挂错卷/相对路径问题）。
- 证书的**公开元数据**：subject、issuer、序列号（`serialNumber`）、`notBefore`/`notAfter`（到期时间，最有排障价值）、SAN、签名算法。这些都来自证书公钥部分，可由 `ssl._ssl._test_decode_cert(path)` 或 `cryptography` 解析。
- 配置型参数：`ssl_version`/TLS 最低版本、`cert_reqs`（是否要求客户端证书，`CERT_NONE/OPTIONAL/REQUIRED`）、`ciphers` 与 ALPN 协议列表、是否设置了口令（**只打“已配置口令”这个布尔，绝不打口令本身**）。
- 指纹（SHA-256 fingerprint）：适合用来比对“实际加载的证书是不是预期那张”，不含私钥。

禁止记录：

- 私钥/key 文件的**任何内容**（含 `BEGIN PRIVATE KEY` 起的 PEM、模数、参数）。
- `ssl_keyfile_password` 口令本身，以及能反推口令的材料。
- 完整证书 PEM 全量转储（信息冗余且易把敏感字段一并带出）；确需留证就记序列号+指纹+到期时间。
- 客户端证书的个人身份字段明细，除非有合规依据；记验证模式与通过/失败结论即可。

建议在调用 uvicorn 前、应用侧先做一次预检并打印上述安全字段（路径、subject/issuer、到期、指纹、验证模式），这样即使 uvicorn 在步①直接 Traceback 退出，也有结构化日志可看，不必回滚去翻文件。

---

## 6. 本地复现步骤（无需生产证书、不监听公网）

一键脚本：`runbook/reproduce.sh`（用仓库 `.venv`，证书即时生成到 `$TMPDIR`，全部绑 `127.0.0.1`）。手动等价命令：

```bash
cd "$TMPDIR" && rm -rf uviclab && mkdir uviclab && cd uviclab
# 自签测试证书 + 损坏件 + 不匹配件
openssl req -x509 -newkey rsa:2048 -nodes -keyout good.key -out good.crt -days 1 -subj "/CN=localhost"
printf 'not-a-certificate\n' > bad.crt
openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.crt -days 1 -subj "/CN=other"

# 阶段一：证书失败 → 退出码 1，纯 Traceback，无 Started server process
python -m uvicorn app_good:app --host 127.0.0.1 --port 18080 \
  --ssl-certfile bad.crt --ssl-keyfile good.key            # ssl.SSLError PEM lib
python -m uvicorn app_good:app --host 127.0.0.1 --port 18080 \
  --ssl-certfile good.crt --ssl-keyfile other.key          # KEY_VALUES_MISMATCH

# 阶段二：lifespan 失败 → 退出码 3（注意必须 --lifespan on 才是硬失败）
python -m uvicorn app_lifespan_fail:app --lifespan on --host 127.0.0.1 --port 18080

# 阶段三：端口占用 → 退出码 3，Application startup complete 之后才报 bind 错
# 真实环境：先起一个进程占用 18080，再启动第二个；本沙箱禁止 bind，故用 stub 抛 EADDRINUSE
python stub_eaddrinuse.py                                   # [Errno 48] Address already in use
```

环境限制说明：本次执行所在沙箱关闭了本地 socket 绑定，任何 `bind()`（含 TCP 与 UNIX 域套接字）都返回 `EPERM (Operation not permitted)`。因此：

- 阶段①、②在创建 socket **之前**失败，已用真实子进程完整复现（退出码与日志均为真实输出）。
- 阶段③用替身精确命中 `server.py:189` 的 `except OSError` 分支复现 `EADDRINUSE`；同时附了一次真实 `bind()` 被沙箱 `EPERM` 拦截的输出，证明同一分支、同一退出码 3、同一日志结构。
- 在允许本地绑定的普通机器上，去掉沙箱限制即可用“先占端口再起第二个进程”的方式复现真实 `EADDRINUSE`，无需替身。如需在本环境启用本地绑定，可由你在设置中开启 `sandbox.network.allowLocalBinding: true`（即时生效，无需重启）。
