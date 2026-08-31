"""Panel module (monitoring): TLS expiry across a list of hosts."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict

from . import Field, Result, Tool, register
from .tls_tool import inspect_host

_SPLIT = re.compile(r"[\s,]+")


def _check(entry: str, default_port: int, timeout: float):
    host, _, port_s = entry.partition(":")
    port = int(port_s) if port_s else default_port
    try:
        _version, _rows, days = inspect_host(host, port, timeout)
        return [host, port, "?" if days is None else days, "ok"]
    except ValueError as exc:
        return [host, port, "-", str(exc)]


def _run(params: Dict[str, str]) -> Result:
    raw = params.get("hosts") or ""
    entries = [e for e in _SPLIT.split(raw.strip()) if e]
    if not entries:
        raise ValueError("at least one host is required")
    if len(entries) > 50:
        raise ValueError("too many hosts (max 50)")
    default_port = int(params.get("port") or 443)
    warn_days = int(params.get("warn_days") or 21)
    timeout = float(params.get("timeout") or 5.0)

    with ThreadPoolExecutor(max_workers=min(20, len(entries))) as pool:
        rows = list(pool.map(lambda e: _check(e, default_port, timeout), entries))
    rows.sort(key=lambda r: (r[3] == "ok", r[2] if isinstance(r[2], int) else 1 << 30))

    def status(row):
        host, port, days, note = row
        if note != "ok":
            return [host, f"{host}:{port}", note, "error"]
        if isinstance(days, int) and days < 0:
            return [host, f"{host}:{port}", f"{days} (EXPIRED)", "error"]
        if isinstance(days, int) and days < warn_days:
            return [host, f"{host}:{port}", f"{days} days", "warn"]
        return [host, f"{host}:{port}", f"{days} days", "ok"]

    table = [[r[1], r[2], r[3]] for r in map(status, rows)]
    worst = "ok"
    for _endpoint, _days, state in table:
        if state == "error":
            worst = "error"
            break
        if state == "warn":
            worst = "warn"

    ok_count = sum(1 for row in table if row[2] == "ok")
    return Result(
        columns=["endpoint", "days remaining", "status"],
        rows=table,
        summary=f"{ok_count}/{len(table)} healthy (warn under {warn_days} days)",
        level=worst,
    )


register(
    Tool(
        name="cert-watch",
        title="Certificate watch",
        description="Check TLS certificate expiry for many hosts at once.",
        category="Network monitoring",
        run=_run,
        fields=[
            Field(
                "hosts",
                "Hosts (one per line, host or host:port)",
                "textarea",
                "example.com\nwww.example.org",
            ),
            Field("port", "Default port", "number", 443, required=False),
            Field("warn_days", "Warn under (days)", "number", 21, required=False),
            Field("timeout", "Timeout (s)", "number", 5.0, required=False),
        ],
    )
)
