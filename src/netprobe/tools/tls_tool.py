"""Panel module: inspect the TLS certificate presented by a host."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List

from . import Field, Result, Tool, register


def _flatten_name(name: Any) -> str:
    # name is a tuple of RDNs, each a tuple of (key, value) pairs
    parts = []
    for rdn in name or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def summarise_cert(cert: Dict[str, Any]) -> List[List[str]]:
    """Turn ``ssl`` getpeercert() output into display rows."""
    rows: List[List[str]] = [
        ["subject", _flatten_name(cert.get("subject"))],
        ["issuer", _flatten_name(cert.get("issuer"))],
    ]
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    if not_before:
        rows.append(["valid from", not_before])
    if not_after:
        rows.append(["valid until", not_after])
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_left = (expires - datetime.now(timezone.utc)).days
        rows.append(["days remaining", str(days_left)])
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    if sans:
        rows.append(["SAN", ", ".join(sans)])
    return rows


def _days_remaining(rows: List[List[str]]) -> "int | None":
    for key, value in rows:
        if key == "days remaining":
            return int(value)
    return None


def inspect_host(host: str, port: int, timeout: float):
    """Connect and return ``(version, rows, days_remaining)``.

    Raises ``ValueError`` on any connection or verification failure.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        raise ValueError(f"certificate verification failed: {exc.verify_message}")
    except (OSError, ssl.SSLError) as exc:
        raise ValueError(f"TLS connection failed: {exc}")

    rows = [["protocol", version or "?"]] + summarise_cert(cert or {})
    return version, rows, _days_remaining(rows)


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    port = int(params.get("port") or 443)
    timeout = float(params.get("timeout") or 5.0)

    version, rows, days = inspect_host(host, port, timeout)
    if days is None:
        level, note = "ok", ""
    elif days < 0:
        level, note = "error", " -- EXPIRED"
    elif days < 14:
        level, note = "warn", f" -- expires in {days} day(s)"
    else:
        level, note = "ok", f" -- {days} day(s) left"

    return Result(
        columns=["field", "value"],
        rows=rows,
        summary=f"{host}:{port} {version}{note}",
        level=level,
    )


register(
    Tool(
        name="tls",
        title="TLS certificate",
        description="Show the certificate a host serves and how long until it expires.",
        run=_run,
        fields=[
            Field("host", "Host", "text", "", "example.com"),
            Field("port", "Port", "number", 443),
            Field("timeout", "Timeout (s)", "number", 5.0, required=False),
        ],
    )
)
