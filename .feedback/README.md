# Feedback task starting environment

Upstream: https://github.com/Kludex/uvicorn
Upstream commit: `a99c1b76ee9caea67ff98e2ccc457bd372db193f`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/middleware/test_proxy_headers.py tests/test_config.py::test_forwarded_allow_ips_default tests/test_config.py::test_config_access_log tests/test_config.py::test_log_config_json
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `249 passed, 20 skipped in 0.79s`
Whole-command wall time: 0.972 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
