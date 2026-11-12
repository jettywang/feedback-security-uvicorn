from __future__ import annotations

import json
import socket
import ssl
from pathlib import Path
from unittest import mock

import pytest

from uvicorn import preflight
from uvicorn.preflight import Finding, PreflightReport, ResolvedOption, run_preflight

SAFE_ARGV = ["service:app", "--host", "127.0.0.1", "--port", "8000"]


def _codes(report: PreflightReport) -> set[tuple[str, str]]:
    return {(finding.severity, finding.code) for finding in report.findings}


def _code_counts(report: PreflightReport) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in report.findings:
        counts[finding.code] = counts.get(finding.code, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Verdict and exit code behaviour
# ---------------------------------------------------------------------------


def test_safe_loopback_config_proceeds() -> None:
    report = run_preflight(SAFE_ARGV, environ={})
    assert report.verdict == "proceed"
    assert report.exit_code == 0
    assert report.findings == []
    assert report.parse_errors == []
    assert report.tls["enabled"] is False


def test_warning_means_review_exit_one() -> None:
    report = run_preflight(["service:app", "--host", "0.0.0.0"], environ={})
    assert report.verdict == "review"
    assert report.exit_code == 1
    assert ("warning", "LISTEN_ALL_INTERFACES") in _codes(report)


def test_error_means_block_exit_two() -> None:
    report = run_preflight(["service:app", "--forwarded-allow-ips", "*"], environ={})
    assert report.verdict == "block"
    assert report.exit_code == 2
    assert ("error", "PROXY_TRUST_WILDCARD") in _codes(report)


# ---------------------------------------------------------------------------
# Precedence: command line > UVICORN_* env > defaults
# ---------------------------------------------------------------------------


def test_cli_overrides_environment() -> None:
    report = run_preflight(
        ["service:app", "--host", "127.0.0.1"],
        environ={"UVICORN_HOST": "0.0.0.0"},
    )
    host = report.effective["host"]
    assert host.value == "127.0.0.1"
    assert host.source == "commandline"


def test_environment_overrides_default() -> None:
    report = run_preflight(["service:app"], environ={"UVICORN_HOST": "::1"})
    host = report.effective["host"]
    assert host.value == "::1"
    assert host.source == "environment"
    assert host.detail == "UVICORN_HOST"


def test_default_is_recorded() -> None:
    report = run_preflight(["service:app"], environ={})
    assert report.effective["port"].value == 8000
    assert report.effective["port"].source == "default"


def test_forwarded_allow_ips_precedence() -> None:
    cli = run_preflight(
        ["service:app", "--forwarded-allow-ips", "10.0.0.1"],
        environ={"FORWARDED_ALLOW_IPS": "10.0.0.2"},
    )
    assert cli.effective["forwarded_allow_ips"].value == "10.0.0.1"
    assert cli.effective["forwarded_allow_ips"].source == "commandline"

    from_env = run_preflight(SAFE_ARGV, environ={"FORWARDED_ALLOW_IPS": "10.0.0.2"})
    resolved = from_env.effective["forwarded_allow_ips"]
    assert resolved.value == "10.0.0.2"
    assert resolved.source == "environment"
    assert resolved.detail == "FORWARDED_ALLOW_IPS"

    default = run_preflight(SAFE_ARGV, environ={})
    assert default.effective["forwarded_allow_ips"].value == "127.0.0.1,::1"
    assert default.effective["forwarded_allow_ips"].source == "default"


def test_web_concurrency_fallback() -> None:
    report = run_preflight(SAFE_ARGV, environ={"WEB_CONCURRENCY": "3"})
    workers = report.effective["workers"]
    assert workers.value == 3
    assert workers.source == "environment"
    assert workers.detail == "WEB_CONCURRENCY"


def test_web_concurrency_malformed_blocks() -> None:
    report = run_preflight(SAFE_ARGV, environ={"WEB_CONCURRENCY": "not-an-int"})
    assert report.verdict == "block"
    assert any("WEB_CONCURRENCY" in error for error in report.parse_errors)


# ---------------------------------------------------------------------------
# Proxy trust auditing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["*", "10.0.0.0/8", "172.16.0.0/12", "2001:db8::/32"],
)
def test_overly_broad_explicit_trust_blocks(value: str) -> None:
    report = run_preflight(
        ["service:app", "--forwarded-allow-ips", value], environ={}
    )
    assert report.verdict == "block"
    assert any(
        finding.severity == "error" and finding.code.startswith("PROXY_TRUST")
        for finding in report.findings
    )


def test_narrow_networks_and_explicit_ips_pass() -> None:
    report = run_preflight(
        ["service:app", "--forwarded-allow-ips", "10.0.0.1,10.1.0.0/24,2001:db8::/48"],
        environ={},
    )
    parsed = report.proxy_trust["forwarded_allow_ips"]["parsed"]
    assert parsed["addresses"] == ["10.0.0.1"]
    assert parsed["networks"] == ["10.1.0.0/24", "2001:db8::/48"]
    assert parsed["malformed"] == []
    assert report.verdict == "proceed"


def test_malformed_entries_are_review_not_silently_trusted() -> None:
    report = run_preflight(
        ["service:app", "--forwarded-allow-ips", "999.1.1.1, , not-an-ip"],
        environ={},
    )
    assert report.verdict == "review"
    parsed = report.proxy_trust["forwarded_allow_ips"]["parsed"]
    assert parsed["malformed"] == ["999.1.1.1", "not-an-ip"]
    assert ("warning", "PROXY_TRUST_MALFORMED_ENTRY") in _codes(report)


def test_wildcard_via_environment_is_detected() -> None:
    report = run_preflight(SAFE_ARGV, environ={"FORWARDED_ALLOW_IPS": "*"})
    assert ("error", "PROXY_TRUST_WILDCARD") in _codes(report)


def test_disabled_proxy_headers_downgrades_trust_findings_to_info() -> None:
    report = run_preflight(
        ["service:app", "--no-proxy-headers", "--forwarded-allow-ips", "*"],
        environ={},
    )
    assert not any(code == "PROXY_TRUST_WILDCARD" for _, code in _codes(report))
    assert ("info", "PROXY_HEADERS_DISABLED") in _codes(report)


# ---------------------------------------------------------------------------
# Listener auditing
# ---------------------------------------------------------------------------


def test_ipv6_wildcard_is_flagged() -> None:
    report = run_preflight(["service:app", "--host", "::"], environ={})
    assert ("warning", "LISTEN_ALL_INTERFACES") in _codes(report)


def test_hostname_is_info_only() -> None:
    report = run_preflight(["service:app", "--host", "localhost"], environ={})
    assert ("info", "HOST_NOT_IP_LITERAL") in _codes(report)


def test_port_out_of_range_blocks() -> None:
    report = run_preflight(["service:app", "--port", "70000"], environ={})
    assert ("error", "PORT_OUT_OF_RANGE") in _codes(report)
    assert report.verdict == "block"


def test_uds_missing_parent_blocks(tmp_path: Path) -> None:
    report = run_preflight(
        ["service:app", "--uds", str(tmp_path / "missing" / "s.sock")], environ={}
    )
    assert ("error", "UDS_PARENT_MISSING") in _codes(report)


def test_negative_fd_blocks() -> None:
    report = run_preflight(["service:app", "--fd", "-1"], environ={})
    assert ("error", "FD_NEGATIVE") in _codes(report)


# ---------------------------------------------------------------------------
# TLS auditing and sensitive handling
# ---------------------------------------------------------------------------


def _make_tls_pair(tmp_path: Path) -> tuple[Path, Path]:
    key_path = tmp_path / "key.pem"
    cert_path = tmp_path / "cert.pem"
    pytest.importorskip("ssl")
    import subprocess

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=preflight",
        ],
        check=True,
        capture_output=True,
    )
    return cert_path, key_path


def test_valid_tls_files_pass(tmp_path: Path) -> None:
    cert_path, key_path = _make_tls_pair(tmp_path)
    report = run_preflight(
        [
            "service:app",
            "--ssl-certfile",
            str(cert_path),
            "--ssl-keyfile",
            str(key_path),
            "--ssl-keyfile-password",
            "secret",
        ],
        environ={},
    )
    assert report.tls["enabled"] is True
    assert report.verdict == "proceed"


def test_missing_tls_files_block_without_reading_them() -> None:
    report = run_preflight(
        [
            "service:app",
            "--ssl-certfile",
            "/nonexistent/cert.pem",
            "--ssl-keyfile",
            "/nonexistent/key.pem",
        ],
        environ={},
    )
    assert report.verdict == "block"
    assert _code_counts(report)["TLS_FILE_MISSING"] == 2


def test_keyfile_without_certfile_blocks(tmp_path: Path) -> None:
    _, key_path = _make_tls_pair(tmp_path)
    report = run_preflight(
        ["service:app", "--ssl-keyfile", str(key_path)], environ={}
    )
    assert ("error", "TLS_CERT_REQUIRED") in _codes(report)


def test_invalid_cipher_list_blocks(tmp_path: Path) -> None:
    cert_path, key_path = _make_tls_pair(tmp_path)
    report = run_preflight(
        [
            "service:app",
            "--ssl-certfile",
            str(cert_path),
            "--ssl-keyfile",
            str(key_path),
            "--ssl-ciphers",
            "NOT-A-CIPHER",
        ],
        environ={},
    )
    assert ("error", "TLS_CIPHERS_INVALID") in _codes(report)


def test_client_auth_without_ca_bundle_warns(tmp_path: Path) -> None:
    cert_path, key_path = _make_tls_pair(tmp_path)
    report = run_preflight(
        [
            "service:app",
            "--ssl-certfile",
            str(cert_path),
            "--ssl-keyfile",
            str(key_path),
            "--ssl-cert-reqs",
            str(int(ssl.CERT_REQUIRED)),
        ],
        environ={},
    )
    assert ("warning", "TLS_CLIENT_AUTH_WITHOUT_CA") in _codes(report)


def test_sensitive_material_is_redacted_everywhere(tmp_path: Path) -> None:
    cert_path, key_path = _make_tls_pair(tmp_path)
    report = run_preflight(
        [
            "service:app",
            "--ssl-certfile",
            str(cert_path),
            "--ssl-keyfile",
            str(key_path),
            "--ssl-keyfile-password",
            "super-secret",
        ],
        environ={},
    )
    serialized = json.dumps(report.to_dict())
    assert "super-secret" not in serialized
    assert str(key_path) not in serialized
    assert report.effective["ssl_keyfile_password"].to_redacted_dict()["value"] == "***REDACTED***"
    assert report.effective["ssl_keyfile"].to_redacted_dict()["value"] == "***REDACTED***"
    assert set(report.redacted) == {"ssl_keyfile", "ssl_keyfile_password"}
    assert report.tls["keyfile"]["value"] == "***REDACTED***"
    assert report.tls["keyfile_password"]["configured"] is True
    assert report.tls["keyfile_password"]["value"] == "***REDACTED***"


# ---------------------------------------------------------------------------
# Parse failures
# ---------------------------------------------------------------------------


def test_bad_integer_environment_blocks() -> None:
    report = run_preflight(["service:app"], environ={"UVICORN_PORT": "abc"})
    assert report.verdict == "block"
    assert report.parse_errors
    assert "valid integer" in report.parse_errors[0]


def test_unknown_option_blocks() -> None:
    report = run_preflight(["service:app", "--does-not-exist"], environ={})
    assert report.verdict == "block"
    assert any("No such option" in error for error in report.parse_errors)


def test_missing_app_blocks() -> None:
    report = run_preflight([], environ={})
    assert report.verdict == "block"
    assert any("APP" in error for error in report.parse_errors)


# ---------------------------------------------------------------------------
# Environment files
# ---------------------------------------------------------------------------


def test_env_file_populates_process_variables(tmp_path: Path) -> None:
    env_file = tmp_path / "platform.env"
    env_file.write_text(
        "# platform supplied\nFORWARDED_ALLOW_IPS=10.0.0.1\nWEB_CONCURRENCY=5\n"
    )
    report = run_preflight(
        ["service:app", f"--env-file={env_file}"], environ={}
    )
    assert report.effective["workers"].value == 5
    assert report.effective["forwarded_allow_ips"].value == "10.0.0.1"


def test_uvicorn_prefixed_vars_in_env_file_are_ignored(tmp_path: Path) -> None:
    # Click resolves UVICORN_* before load_dotenv() runs, matching uvicorn itself.
    env_file = tmp_path / "platform.env"
    env_file.write_text("UVICORN_HOST=10.9.9.9\nFORWARDED_ALLOW_IPS=10.0.0.1\n")
    report = run_preflight(["service:app", f"--env-file={env_file}"], environ={})
    assert report.effective["host"].value == "127.0.0.1"
    assert report.effective["host"].source == "default"
    assert report.effective["forwarded_allow_ips"].value == "10.0.0.1"


def test_process_environment_beats_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / "platform.env"
    env_file.write_text("FORWARDED_ALLOW_IPS=10.0.0.1\n")
    report = run_preflight(
        ["service:app", f"--env-file={env_file}"],
        environ={"FORWARDED_ALLOW_IPS": "10.0.0.2"},
    )
    assert report.effective["forwarded_allow_ips"].value == "10.0.0.2"


def test_missing_env_file_blocks(tmp_path: Path) -> None:
    report = run_preflight(
        ["service:app", f"--env-file={tmp_path / 'missing.env'}"], environ={}
    )
    assert ("error", "ENV_FILE_UNREADABLE") in _codes(report)


def test_malformed_env_file_blocks(tmp_path: Path) -> None:
    env_file = tmp_path / "bad.env"
    env_file.write_text("THIS IS NOT KEY VALUE\n")
    report = run_preflight(["service:app", f"--env-file={env_file}"], environ={})
    assert ("error", "ENV_FILE_MALFORMED") in _codes(report)


# ---------------------------------------------------------------------------
# Side-effect guarantees
# ---------------------------------------------------------------------------


def test_no_socket_is_opened() -> None:
    created: list[tuple[object, object]] = []

    def tracking_socket(*args: object, **kwargs: object) -> socket.socket:
        created.append((args, kwargs))
        return real_socket(*args, **kwargs)

    real_socket = socket.socket
    with mock.patch("socket.socket", side_effect=tracking_socket):
        run_preflight(["service:app", "--host", "0.0.0.0", "--port", "9999"], environ={})
    assert created == []


def test_application_is_not_imported() -> None:
    forbidden = mock.MagicMock(side_effect=AssertionError("app was imported"))
    with mock.patch.dict("sys.modules", {"never_imported_service": mock.MagicMock(app=forbidden)}):
        run_preflight(["never_imported_service:app"], environ={})
    assert forbidden.call_count == 0


def test_tls_files_are_never_opened(tmp_path: Path) -> None:
    cert_path, key_path = _make_tls_pair(tmp_path)
    opened: list[str] = []
    real_open = open

    def tracking_open(file: object, *args: object, **kwargs: object) -> object:
        opened.append(str(file))
        return real_open(file, *args, **kwargs)  # type: ignore[arg-type]

    with mock.patch("builtins.open", side_effect=tracking_open):
        run_preflight(
            [
                "service:app",
                "--ssl-certfile",
                str(cert_path),
                "--ssl-keyfile",
                str(key_path),
            ],
            environ={},
        )
    assert str(key_path) not in opened
    assert str(cert_path) not in opened


# ---------------------------------------------------------------------------
# Report shape and CLI
# ---------------------------------------------------------------------------


def test_report_json_is_platform_serializable() -> None:
    report = run_preflight(
        ["service:app", "--host", "0.0.0.0", "--forwarded-allow-ips", "*"],
        environ={},
    )
    payload = report.to_dict()
    assert payload["schema_version"] == preflight.SCHEMA_VERSION
    assert payload["verdict"] == "block"
    assert {"listener", "proxy_trust", "tls", "effective", "findings", "redaction"} <= set(payload)
    json.loads(json.dumps(payload))


def test_main_text_rendering_and_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = preflight.main(["--format", "text", "service:app", "--host", "0.0.0.0"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "REVIEW" in captured.out
    assert "LISTEN_ALL_INTERFACES" in captured.out


def test_main_writes_output_file(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    exit_code = preflight.main(
        ["--output", str(target), "service:app", "--host", "127.0.0.1"]
    )
    payload = json.loads(target.read_text())
    assert exit_code == 0
    assert payload["verdict"] == "proceed"


def test_finding_and_resolved_option_dataclasses() -> None:
    finding = Finding(severity="info", code="X", message="m")
    assert "setting" not in finding.to_dict()
    option = ResolvedOption("name", "value", "default")
    assert option.to_dict() == {"value": "value", "source": "default"}
    assert option.to_redacted_dict()["value"] == "***REDACTED***"
