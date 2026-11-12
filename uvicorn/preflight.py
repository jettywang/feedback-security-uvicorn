"""Pre-listen configuration inspection for operations platforms.

This module answers one question: *given the environment and command line that
will be handed to ``uvicorn``, what would the running process actually trust and
bind, and is any of it unsafe or malformed?*

It deliberately stops short of what :func:`uvicorn.main.run` does next:

* the application import string is never imported, so no application code runs;
* no socket is created or bound, so no port or UNIX domain socket is opened;
* no SSL context is loaded with a private key, so key material never leaves the
  file system and key passwords are never echoed back.

The effective configuration is resolved with the real Click command defined in
:mod:`uvicorn.main`, so the precedence (command line > ``UVICORN_*`` environment
variables > documented defaults) and the type coercion are the ones Uvicorn
itself uses rather than a hand-written copy.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import ssl
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Mapping
from unittest import mock

import click

from uvicorn.main import main as uvicorn_cli

SCHEMA_VERSION = "1"

Severity = Literal["error", "warning", "info"]
Verdict = Literal["block", "review", "proceed"]
SourceKind = Literal["default", "environment", "commandline"]

DEFAULT_FORWARDED_ALLOW_IPS = "127.0.0.1,::1"
SENSITIVE_OUTPUT = "***REDACTED***"

# Option names whose values are treated as platform-sensitive material.
SENSITIVE_OPTIONS = frozenset({"ssl_keyfile", "ssl_keyfile_password"})

_CERT_REQS_NAMES = {
    int(ssl.CERT_NONE): "CERT_NONE",
    int(ssl.CERT_OPTIONAL): "CERT_OPTIONAL",
    int(ssl.CERT_REQUIRED): "CERT_REQUIRED",
}


_UNSET: Any = object()


@dataclass
class Finding:
    """A single preflight observation."""

    severity: Severity
    code: str
    message: str
    setting: str | None = None
    value: Any = _UNSET

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }
        if self.setting is not None:
            data["setting"] = self.setting
        if self.value is not _UNSET:
            data["value"] = self.value
        return data


@dataclass
class ResolvedOption:
    """An option value together with where it came from."""

    name: str
    value: Any
    source: SourceKind
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {"value": self.value, "source": self.source}
        if self.detail is not None:
            data["detail"] = self.detail
        return data

    def to_redacted_dict(self) -> dict[str, Any]:
        data = self.to_dict()
        data["value"] = SENSITIVE_OUTPUT
        return data


@dataclass
class PreflightReport:
    """Structured result consumed by the operations platform."""

    effective: dict[str, ResolvedOption]
    findings: list[Finding] = field(default_factory=list)
    redacted: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    env_file: str | None = None
    listener: dict[str, Any] = field(default_factory=dict)
    proxy_trust: dict[str, Any] = field(default_factory=dict)
    tls: dict[str, Any] = field(default_factory=dict)

    @property
    def verdict(self) -> Verdict:
        if any(item.severity == "error" for item in self.findings) or self.parse_errors:
            return "block"
        if any(item.severity == "warning" for item in self.findings):
            return "review"
        return "proceed"

    @property
    def exit_code(self) -> int:
        return {"block": 2, "review": 1, "proceed": 0}[self.verdict]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(UTC).isoformat(),
            "verdict": self.verdict,
            "summary": {
                "errors": sum(1 for item in self.findings if item.severity == "error"),
                "warnings": sum(1 for item in self.findings if item.severity == "warning"),
                "infos": sum(1 for item in self.findings if item.severity == "info"),
                "parse_errors": len(self.parse_errors),
                "redacted": len(self.redacted),
            },
            "listener": self.listener,
            "proxy_trust": self.proxy_trust,
            "tls": self.tls,
            "effective": {
                name: (
                    option.to_redacted_dict()
                    if name in SENSITIVE_OPTIONS and option.value is not None
                    else option.to_dict()
                )
                for name, option in self.effective.items()
            },
            "findings": [item.to_dict() for item in self.findings],
            "redaction": {
                "policy": "TLS private key paths and key credentials are never emitted",
                "redacted_fields": self.redacted,
            },
            "parsing": {
                "env_file": self.env_file,
                "errors": self.parse_errors,
            },
        }


# ---------------------------------------------------------------------------
# Environment file handling
# ---------------------------------------------------------------------------


def _parse_env_file(path: str | os.PathLike[str]) -> dict[str, str]:
    """Parse a small ``KEY=VALUE`` dotenv file without importing python-dotenv.

    Only the subset needed to populate process environment variables is
    supported: comments, blank lines, optional ``export`` and surrounding
    quotes. ``python-dotenv`` interpolation is intentionally not implemented.
    """

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(Path(path).read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: expected KEY=VALUE, got {raw_line!r}")
        key, _, raw_value = line.partition("=")
        key = key.strip()
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def _extract_env_file(argv: list[str]) -> tuple[str | None, list[str]]:
    """Return the ``--env-file`` target while keeping the argv untouched otherwise."""

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--env-file", dest="env_file")
    namespace, remaining = parser.parse_known_args(list(argv))
    return namespace.env_file, remaining


def _build_environment(
    environ: Mapping[str, str], env_file: str | None
) -> tuple[dict[str, str], dict[str, str], list[Finding]]:
    merged = dict(environ)
    findings: list[Finding] = []
    if env_file is None:
        return merged, {}, findings

    try:
        file_values = _parse_env_file(env_file)
    except OSError as exc:
        findings.append(
            Finding(
                severity="error",
                code="ENV_FILE_UNREADABLE",
                message=f"Environment file cannot be read: {exc}",
                setting="env_file",
                value=env_file,
            )
        )
        return merged, {}, findings
    except ValueError as exc:
        findings.append(
            Finding(
                severity="error",
                code="ENV_FILE_MALFORMED",
                message=f"Environment file is malformed: {exc}",
                setting="env_file",
                value=env_file,
            )
        )
        return merged, {}, findings

    # Mirrors load_dotenv(): real process variables win over the file.
    for key, value in file_values.items():
        merged.setdefault(key, value)
    return merged, file_values, findings


# ---------------------------------------------------------------------------
# Click resolution
# ---------------------------------------------------------------------------


def _source_kind(source: click.core.ParameterSource) -> SourceKind:
    return {
        click.core.ParameterSource.DEFAULT: "default",
        click.core.ParameterSource.ENVIRONMENT: "environment",
        click.core.ParameterSource.COMMANDLINE: "commandline",
    }[source]


def _option_envvar(parameter: click.Parameter) -> str | None:
    envvar = parameter.envvar
    if isinstance(envvar, str):
        return envvar
    if isinstance(envvar, (list, tuple)) and envvar:
        return str(envvar[0])
    # The uvicorn command relies on auto_envvar_prefix="UVICORN" instead of
    # declaring an envvar on each parameter.
    if parameter.name is not None:
        return f"UVICORN_{parameter.name.upper()}"
    return None


def _resolve_click(
    argv: list[str], environ: Mapping[str, str]
) -> tuple[dict[str, ResolvedOption], list[str]]:
    """Resolve every CLI option through Uvicorn's real Click command."""

    parse_errors: list[str] = []
    try:
        with mock.patch.dict(os.environ, dict(environ), clear=True):
            ctx = uvicorn_cli.make_context("uvicorn", list(argv))
    except click.UsageError as exc:
        parse_errors.append(exc.format_message())
        with mock.patch.dict(os.environ, dict(environ), clear=True):
            ctx = uvicorn_cli.make_context("uvicorn", list(argv), resilient_parsing=True)
    ctx.close()

    resolved: dict[str, ResolvedOption] = {}
    for parameter in ctx.command.params:
        if parameter.name is None:
            continue
        source = ctx.get_parameter_source(parameter.name)
        value = ctx.params.get(parameter.name)
        detail: str | None = None
        if source == click.core.ParameterSource.ENVIRONMENT:
            detail = _option_envvar(parameter)
        resolved[parameter.name] = ResolvedOption(
            name=parameter.name,
            value=value,
            source=_source_kind(source),
            detail=detail,
        )
    return resolved, parse_errors


# ---------------------------------------------------------------------------
# Individual check areas
# ---------------------------------------------------------------------------


def _split_entries(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip() != ""]


def check_proxy_trust(
    options: dict[str, ResolvedOption],
    environ: Mapping[str, str],
    findings: list[Finding],
) -> dict[str, Any]:
    """Resolve and audit the proxy headers trust boundary."""

    proxy_headers = options["proxy_headers"].value
    cli_option = options["forwarded_allow_ips"]

    raw_value: Any
    source: SourceKind
    detail: str | None = None
    if cli_option.value is not None:
        raw_value = cli_option.value
        source = cli_option.source
        detail = cli_option.detail
    elif "FORWARDED_ALLOW_IPS" in environ:
        raw_value = environ["FORWARDED_ALLOW_IPS"]
        source = "environment"
        detail = "FORWARDED_ALLOW_IPS"
    else:
        raw_value = DEFAULT_FORWARDED_ALLOW_IPS
        source = "default"
        detail = "FORWARDED_ALLOW_IPS"

    entries = _split_entries(str(raw_value))
    always_trust = entries == ["*"]

    literals: list[str] = []
    addresses: list[str] = []
    networks: list[str] = []
    malformed: list[str] = []

    for entry in entries:
        if entry == "*":
            continue
        if "/" in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                malformed.append(entry)
                literals.append(entry)
                continue
            networks.append(str(network))
        else:
            try:
                address = ipaddress.ip_address(entry)
            except ValueError:
                malformed.append(entry)
                literals.append(entry)
            else:
                addresses.append(str(address))

    # De-duplicate while preserving order for a stable report.
    networks = list(dict.fromkeys(networks))
    addresses = list(dict.fromkeys(addresses))
    literals = list(dict.fromkeys(literals))
    malformed = list(dict.fromkeys(malformed))

    if proxy_headers:
        if always_trust:
            findings.append(
                Finding(
                    severity="error",
                    code="PROXY_TRUST_WILDCARD",
                    message=(
                        "Forwarded headers are trusted from every peer ('*'). Spoofed "
                        "X-Forwarded-For/X-Forwarded-Proto headers will be accepted."
                    ),
                    setting="forwarded_allow_ips",
                    value="*",
                )
            )
        for entry in networks:
            network = ipaddress.ip_network(entry)
            threshold = 24 if network.version == 4 else 48
            if network.prefixlen < threshold:
                findings.append(
                    Finding(
                        severity="error",
                        code="PROXY_TRUST_OVERLY_BROAD_NETWORK",
                        message=(
                            f"Trusted proxy network {entry} spans more than a /{threshold}; "
                            "narrow it to the proxy addresses you actually operate."
                        ),
                        setting="forwarded_allow_ips",
                        value=entry,
                    )
                )
        if malformed:
            findings.append(
                Finding(
                    severity="warning",
                    code="PROXY_TRUST_MALFORMED_ENTRY",
                    message=(
                        "Entries are not valid IP addresses or networks, so Uvicorn falls "
                        "back to literal string matching that can never match an IP peer."
                    ),
                    setting="forwarded_allow_ips",
                    value=malformed,
                )
            )
    else:
        findings.append(
            Finding(
                severity="info",
                code="PROXY_HEADERS_DISABLED",
                message="Proxy header processing is disabled; the trust list is not consulted.",
                setting="proxy_headers",
                value=False,
            )
        )

    return {
        "proxy_headers": proxy_headers,
        "forwarded_allow_ips": {
            "value": str(raw_value),
            "source": source,
            "detail": detail,
            "parsed": {
                "always_trust": always_trust,
                "addresses": addresses,
                "networks": networks,
                "literals": literals,
                "malformed": malformed,
            },
        },
    }


def check_listen(
    options: dict[str, ResolvedOption], findings: list[Finding]
) -> dict[str, Any]:
    """Describe the endpoint Uvicorn would bind without opening any socket."""

    host = options["host"].value
    port = options["port"].value
    uds = options["uds"].value
    fd = options["fd"].value

    endpoint: dict[str, Any]
    if uds is not None:
        endpoint = {"kind": "unix", "path": uds}
        parent = Path(uds).parent
        if not parent.exists():
            findings.append(
                Finding(
                    severity="error",
                    code="UDS_PARENT_MISSING",
                    message=f"UNIX socket parent directory does not exist: {parent}",
                    setting="uds",
                    value=uds,
                )
            )
    elif fd is not None:
        endpoint = {"kind": "fd", "fd": fd}
        if fd < 0:
            findings.append(
                Finding(
                    severity="error",
                    code="FD_NEGATIVE",
                    message="File descriptor must be a non-negative integer.",
                    setting="fd",
                    value=fd,
                )
            )
    else:
        endpoint = {"kind": "tcp", "host": host, "port": port}
        if not isinstance(port, int) or not (0 <= port <= 65535):
            findings.append(
                Finding(
                    severity="error",
                    code="PORT_OUT_OF_RANGE",
                    message="Port must be an integer between 0 and 65535.",
                    setting="port",
                    value=port,
                )
            )
        if host is None:
            findings.append(
                Finding(
                    severity="error",
                    code="HOST_UNRESOLVED",
                    message="Host could not be parsed; see the blocking parse errors.",
                    setting="host",
                )
            )
        elif isinstance(host, str):
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                findings.append(
                    Finding(
                        severity="info",
                        code="HOST_NOT_IP_LITERAL",
                        message="Host is not an IP literal; it will be resolved at bind time.",
                        setting="host",
                        value=host,
                    )
                )
            else:
                if address.is_unspecified:
                    findings.append(
                        Finding(
                            severity="warning",
                            code="LISTEN_ALL_INTERFACES",
                            message=(
                                "The listener binds every interface and accepts connections "
                                "from the network, not just the local machine."
                            ),
                            setting="host",
                            value=host,
                        )
                    )

    return {
        "endpoint": endpoint,
        "sources": {
            "host": options["host"].source,
            "port": options["port"].source,
            "uds": options["uds"].source,
            "fd": options["fd"].source,
        },
    }


def _check_existing_file(path: Any, setting: str, findings: list[Finding]) -> None:
    if path is None:
        return
    candidate = Path(path)
    if not candidate.exists():
        findings.append(
            Finding(
                severity="error",
                code="TLS_FILE_MISSING",
                message="Configured file does not exist.",
                setting=setting,
                value=SENSITIVE_OUTPUT if setting == "ssl_keyfile" else str(candidate),
            )
        )
    elif not candidate.is_file():
        findings.append(
            Finding(
                severity="error",
                code="TLS_FILE_NOT_REGULAR",
                message="Configured path is not a regular file.",
                setting=setting,
                value=SENSITIVE_OUTPUT if setting == "ssl_keyfile" else str(candidate),
            )
        )
    elif not os.access(candidate, os.R_OK):
        findings.append(
            Finding(
                severity="error",
                code="TLS_FILE_UNREADABLE",
                message="Configured file exists but is not readable.",
                setting=setting,
                value=SENSITIVE_OUTPUT if setting == "ssl_keyfile" else str(candidate),
            )
        )


def check_tls(
    options: dict[str, ResolvedOption],
    findings: list[Finding],
    redacted: list[str],
) -> dict[str, Any]:
    """Audit TLS options through metadata and crypto checks that never load a key."""

    certfile = options["ssl_certfile"].value
    keyfile = options["ssl_keyfile"].value
    password_set = options["ssl_keyfile_password"].value is not None
    version = options["ssl_version"].value
    cert_reqs = options["ssl_cert_reqs"].value
    ca_certs = options["ssl_ca_certs"].value
    ciphers = options["ssl_ciphers"].value

    tls_enabled = bool(certfile or keyfile)
    result: dict[str, Any] = {
        "enabled": tls_enabled,
        "certfile": _option_view(options["ssl_certfile"]),
        "keyfile": _sensitive_view(options["ssl_keyfile"], redacted),
        "keyfile_password": {
            "source": options["ssl_keyfile_password"].source,
            "detail": options["ssl_keyfile_password"].detail,
            "configured": password_set,
            "value": SENSITIVE_OUTPUT if password_set else None,
        },
        "version": _option_view(options["ssl_version"]),
        "cert_reqs": _option_view(options["ssl_cert_reqs"]),
        "ca_certs": _option_view(options["ssl_ca_certs"]),
        "ciphers": _option_view(options["ssl_ciphers"]),
    }

    if not tls_enabled:
        result["protocol"] = "plaintext"
        return result

    result["protocol"] = "tls"

    if not certfile:
        findings.append(
            Finding(
                severity="error",
                code="TLS_CERT_REQUIRED",
                message="A TLS key file was given without a certificate file; ssl_certfile is mandatory.",
                setting="ssl_certfile",
                value=None,
            )
        )
    _check_existing_file(certfile, "ssl_certfile", findings)
    _check_existing_file(keyfile, "ssl_keyfile", findings)
    _check_existing_file(ca_certs, "ssl_ca_certs", findings)

    try:
        context = ssl.SSLContext(int(version))
    except (ValueError, TypeError) as exc:
        findings.append(
            Finding(
                severity="error",
                code="TLS_VERSION_INVALID",
                message=f"ssl_version is not a usable protocol: {exc}",
                setting="ssl_version",
                value=version,
            )
        )
    else:
        if ciphers is not None:
            try:
                context.set_ciphers(str(ciphers))
            except ssl.SSLError as exc:
                findings.append(
                    Finding(
                        severity="error",
                        code="TLS_CIPHERS_INVALID",
                        message=f"OpenSSL rejects the configured cipher list: {exc}",
                        setting="ssl_ciphers",
                        value=ciphers,
                    )
                )

    try:
        cert_reqs_key = int(cert_reqs)
    except (ValueError, TypeError):
        cert_reqs_key = -1
    cert_reqs_name = _CERT_REQS_NAMES.get(cert_reqs_key)
    if cert_reqs_name is None:
        findings.append(
            Finding(
                severity="warning",
                code="TLS_CERT_REQS_UNKNOWN",
                message="ssl_cert_reqs is not one of CERT_NONE, CERT_OPTIONAL or CERT_REQUIRED.",
                setting="ssl_cert_reqs",
                value=cert_reqs,
            )
        )
    elif cert_reqs_name in {"CERT_OPTIONAL", "CERT_REQUIRED"} and not ca_certs:
        findings.append(
            Finding(
                severity="warning",
                code="TLS_CLIENT_AUTH_WITHOUT_CA",
                message=(
                    f"Client certificates are requested ({cert_reqs_name}) but no CA bundle "
                    "is configured, so peers cannot be verified."
                ),
                setting="ssl_ca_certs",
            )
        )

    return result


def _option_view(option: ResolvedOption) -> dict[str, Any]:
    return {
        "value": option.value,
        "source": option.source,
        "detail": option.detail,
        "configured": option.value is not None,
    }


def _sensitive_view(
    option: ResolvedOption, redacted: list[str]
) -> dict[str, Any]:
    configured = option.value is not None
    if configured and option.name not in redacted:
        redacted.append(option.name)
    return {
        "source": option.source,
        "detail": option.detail,
        "configured": configured,
        "value": SENSITIVE_OUTPUT if configured else None,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_preflight(
    argv: list[str], environ: Mapping[str, str] | None = None
) -> PreflightReport:
    """Build the preflight report for ``argv`` against ``environ``."""

    env_file, remaining = _extract_env_file(argv)
    environment, env_file_values, env_findings = _build_environment(
        environ or os.environ, env_file
    )

    # Click reads UVICORN_* before load_dotenv() runs, so variables that only
    # exist in the environment file must not be offered to the Click resolver.
    click_environment = {
        key: value
        for key, value in environment.items()
        if not (key.startswith("UVICORN_") and key in env_file_values)
    }
    options, parse_errors = _resolve_click(remaining, click_environment)
    findings = list(env_findings)

    # Config-level fallbacks that Click cannot express (see uvicorn.config.Config).
    workers = options["workers"]
    if workers.value is None:
        if "WEB_CONCURRENCY" in environment:
            try:
                workers = ResolvedOption(
                    "workers",
                    int(environment["WEB_CONCURRENCY"]),
                    "environment",
                    "WEB_CONCURRENCY",
                )
            except ValueError:
                parse_errors.append(
                    f"WEB_CONCURRENCY must be an integer, got {environment['WEB_CONCURRENCY']!r}."
                )
        else:
            workers = ResolvedOption("workers", 1, "default", "workers")
    options["workers"] = workers

    listen = check_listen(options, findings)
    proxy = check_proxy_trust(options, environment, findings)
    redacted: list[str] = []
    tls = check_tls(options, findings, redacted)

    if tls["enabled"] and isinstance(listen["endpoint"], dict) and listen["endpoint"].get("kind") == "tcp":
        host = listen["endpoint"].get("host")
        try:
            address = ipaddress.ip_address(host)
        except (ValueError, TypeError):
            address = None
        if address is not None and address.is_unspecified:
            findings.append(
                Finding(
                    severity="info",
                    code="TLS_ON_WILDCARD_LISTENER",
                    message="TLS is enabled on a wildcard listener; verify firewall exposure as well.",
                    setting="ssl_certfile",
                )
            )

    effective: dict[str, ResolvedOption] = {}
    for name in (
        "app",
        "host",
        "port",
        "uds",
        "fd",
        "proxy_headers",
        "workers",
        "ssl_version",
        "ssl_cert_reqs",
        "ssl_certfile",
        "ssl_ca_certs",
        "ssl_ciphers",
    ):
        effective[name] = options[name]
    effective["forwarded_allow_ips"] = ResolvedOption(
        "forwarded_allow_ips",
        proxy["forwarded_allow_ips"]["value"],
        proxy["forwarded_allow_ips"]["source"],
        proxy["forwarded_allow_ips"]["detail"],
    )
    effective["ssl_keyfile"] = options["ssl_keyfile"]
    effective["ssl_keyfile_password"] = options["ssl_keyfile_password"]

    for sensitive_name in SENSITIVE_OPTIONS:
        if effective[sensitive_name].value is not None and sensitive_name not in redacted:
            redacted.append(sensitive_name)

    return PreflightReport(
        effective=effective,
        findings=findings,
        redacted=redacted,
        parse_errors=parse_errors,
        env_file=env_file,
        listener=listen,
        proxy_trust=proxy,
        tls=tls,
    )


def render_text(report: PreflightReport) -> str:
    """Human-readable rendering for the on-call terminal."""

    data = report.to_dict()
    lines = [
        f"Uvicorn preflight verdict: {report.verdict.upper()} (exit {report.exit_code})",
        "",
        "Listener: " + json.dumps(data["listener"], ensure_ascii=False),
        "Proxy trust: " + json.dumps(data["proxy_trust"], ensure_ascii=False),
        "TLS: " + json.dumps(data["tls"], ensure_ascii=False),
        "",
        "Effective configuration:",
    ]
    for name, option in data["effective"].items():
        lines.append(f"  - {name}: {option['value']!r} [{option['source']}]")

    lines.append("")
    if report.findings:
        lines.append("Findings:")
        for finding in report.findings:
            lines.append(
                f"  - [{finding.severity.upper():7}] {finding.code}: {finding.message}"
            )
    else:
        lines.append("Findings: none")

    if report.parse_errors:
        lines.append("")
        lines.append("Blocking parse errors:")
        lines.extend(f"  - {error}" for error in report.parse_errors)

    lines.append("")
    lines.append("Redacted fields: " + (", ".join(report.redacted) if report.redacted else "none"))
    return "\n".join(lines)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m uvicorn.preflight",
        description=(
            "Inspect the Uvicorn configuration that would take effect, without "
            "importing the application or opening a socket."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Output format consumed by the operator or the on-call terminal.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write the report to this path instead of standard output.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    namespace, uvicorn_argv = parser.parse_known_args(argv)
    report = run_preflight(uvicorn_argv)

    rendered = (
        json.dumps(report.to_dict(), indent=2, sort_keys=False, ensure_ascii=False)
        if namespace.format == "json"
        else render_text(report)
    )
    if namespace.output is not None:
        Path(namespace.output).write_text(rendered + "\n")
    else:
        click.echo(rendered)
    return report.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
