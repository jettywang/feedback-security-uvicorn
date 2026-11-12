# Pre-listen configuration preflight

An operations platform can ask Uvicorn to report the configuration that *would*
take effect before the process starts listening. The preflight resolves the real
command line and environment, audits the trusted proxy boundary, the listen
address and the TLS options, and emits a machine-readable verdict — without ever
opening a socket, importing the application, or reading a private key.

## Running the preflight

The preflight is a separate entry point that accepts the same arguments and
`UVICORN_*` environment variables as the `uvicorn` command:

```bash
python -m uvicorn.preflight [--format json|text] [--output FILE] [-- <uvicorn args>]
```

The `--` separator is optional because preflight-specific flags are parsed
liberally; every remaining token is handed straight to Uvicorn's own Click
command. For example:

```bash
python -m uvicorn.preflight payments.main:app \
    --host 127.0.0.1 --port 8443 \
    --forwarded-allow-ips 10.0.1.5,10.0.1.6
```

The same invocation works inside Python, which is convenient for tests and for
platforms that already hold an environment mapping:

```python
from uvicorn.preflight import run_preflight

report = run_preflight(
    ["payments.main:app", "--host", "127.0.0.1"],
    environ={"FORWARDED_ALLOW_IPS": "10.0.1.5"},
)
print(report.verdict, report.exit_code)
```

## What is guaranteed not to happen

* The `APP` import string is never resolved, so no application module is imported
  and no application code runs.
* No TCP, UNIX domain or inherited-descriptor socket is created or bound; the
  listener is described from the resolved values only.
* No `ssl.SSLContext` is loaded with a certificate chain. TLS files are checked
  for existence and readability, the protocol version and cipher list are probed
  against an in-memory context, and the private key itself is never opened.

## Resolution precedence

The preflight reuses Uvicorn's actual Click command rather than re-implementing
parsing, so the precedence matches a real launch exactly:

1. Command line options.
2. `UVICORN_*` environment variables (for example `UVICORN_HOST`).
3. Documented defaults.

Two values are resolved later, inside `Config`, and the preflight mirrors that
logic and records their provenance:

* `--forwarded-allow-ips` falls back to `FORWARDED_ALLOW_IPS`, then to
  `127.0.0.1,::1`.
* `--workers` falls back to `WEB_CONCURRENCY`, then to `1`.

When `--env-file` is given, its `KEY=VALUE` entries populate variables that are
not already present in the process environment, matching `load_dotenv()`
semantics. As with Uvicorn itself, `UVICORN_*` settings inside an environment
file are ignored by Click; the file is intended for application settings such as
`FORWARDED_ALLOW_IPS` and `WEB_CONCURRENCY`.

## Verdicts and exit codes

| Verdict   | Exit code | Meaning for the on-call engineer |
| --------- | --------- | -------------------------------- |
| `proceed` | 0         | No blocking or reviewable findings. |
| `review`  | 1         | Only warnings or informational findings; a human should confirm. |
| `block`   | 2         | At least one error or an unparseable command line/environment. |

Findings carry a stable machine-readable `code`. The main groups are:

* **Proxy trust** — `PROXY_TRUST_WILDCARD` (the literal `*`),
  `PROXY_TRUST_OVERLY_BROAD_NETWORK` (IPv4 wider than `/24` or IPv6 wider than
  `/48`), and `PROXY_TRUST_MALFORMED_ENTRY` (values that are neither valid IP
  addresses nor networks and therefore degrade to literal string matching).
* **Listener** — `LISTEN_ALL_INTERFACES` (`0.0.0.0` / `::`),
  `HOST_NOT_IP_LITERAL`, `PORT_OUT_OF_RANGE`, `UDS_PARENT_MISSING`,
  `FD_NEGATIVE`.
* **TLS** — `TLS_CERT_REQUIRED`, `TLS_FILE_MISSING`, `TLS_FILE_NOT_REGULAR`,
  `TLS_FILE_UNREADABLE`, `TLS_VERSION_INVALID`, `TLS_CIPHERS_INVALID`,
  `TLS_CERT_REQS_UNKNOWN`, `TLS_CLIENT_AUTH_WITHOUT_CA`.
* **Environment files** — `ENV_FILE_UNREADABLE`, `ENV_FILE_MALFORMED`.

When `--no-proxy-headers` is set, the trust list is reported for visibility but
its over-broad or malformed entries are downgraded to a single
`PROXY_HEADERS_DISABLED` informational finding, because Uvicorn will not consult
the list at runtime.

## Sensitive values

TLS private key paths and key passwords are platform-sensitive. The preflight
never emits them:

* `ssl_keyfile` and `ssl_keyfile_password` appear as `***REDACTED***` everywhere
  in the report, including the generic `effective` section and any finding.
* A key file is still audited (existence, regular-file and readability), and the
  password is still reported as `configured: true`/`false`, so the platform can
  reason about them without seeing the material.
* The `redaction.redacted_fields` array lists every field that was masked.

## Report shape

The JSON document has a stable top-level layout:

* `schema_version`, `generated_at`, `verdict` and a `summary` of finding counts.
* `listener`, `proxy_trust` and `tls` — structured, normalized views of the three
  audited areas.
* `effective` — every relevant option with its resolved `value`, its `source`
  (`default`, `environment` or `commandline`) and, for environment-sourced
  values, the variable name in `detail`.
* `findings` — the ordered list of observations.
* `redaction` — the masking policy and the fields it was applied to.
* `parsing` — the environment file used and any blocking parse errors.

## Worked examples

The `deployment/preflight-examples/` directory contains reports generated by the
tool itself, so they can be diffed when the schema changes:

* [`effective-config.json`](preflight-examples/effective-config.json) — a clean
  loopback listener with an explicit, narrow proxy trust list (`proceed`).
* [`overly-broad-rules.json`](preflight-examples/overly-broad-rules.json) — a
  wildcard listener plus `--forwarded-allow-ips '*'`, showing blocking errors and
  redacted TLS material (`block`).
* [`malformed-config.json`](preflight-examples/malformed-config.json) — an
  unparseable port, an over-wide network and malformed trust entries (`block`).
* [`on-call-text.txt`](preflight-examples/on-call-text.txt) — the same data in
  the terminal-oriented text rendering.
