"""Panel module (monitoring): up/down status for a list of hosts."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict

from ..scanner import tcp_latency
from . import Field, Result, Tool, register

_SPLIT = re.compile(r"[\s,]+")


def _check(entry: str, default_port: int, timeout: float):
    host, _, port_s = entry.partition(":")
    port = int(port_s) if port_s else default_port
    (latency,) = tcp_latency(host, port, count=1, timeout=timeout)
    if latency is None:
        return [f"{host}:{port}", "DOWN", "-", "error"]
    return [f"{host}:{port}", "UP", f"{latency} ms", "ok"]


def _run(params: Dict[str, str]) -> Result:
    raw = params.get("hosts") or ""
    entries = [e for e in _SPLIT.split(raw.strip()) if e]
    if not entries:
        raise ValueError("at least one host is required")
    if len(entries) > 100:
        raise ValueError("too many hosts (max 100)")
    default_port = int(params.get("port") or 80)
    timeout = float(params.get("timeout") or 2.0)

    with ThreadPoolExecutor(max_workers=min(50, len(entries))) as pool:
        rows = list(pool.map(lambda e: _check(e, default_port, timeout), entries))
    rows.sort(key=lambda r: r[3] == "ok")

    table = [[r[0], r[1], r[2]] for r in rows]
    up = sum(1 for r in rows if r[3] == "ok")
    level = "ok" if up == len(rows) else "error" if up == 0 else "warn"
    return Result(
        columns=["endpoint", "state", "rtt"],
        rows=table,
        summary=f"{up}/{len(rows)} up on port {default_port}",
        level=level,
    )


register(
    Tool(
        name="hosts",
        title="Host status",
        description="Check a list of hosts for a reachable TCP port and show up/down.",
        category="Network monitoring",
        run=_run,
        fields=[
            Field(
                "hosts",
                "Hosts (one per line, host or host:port)",
                "textarea",
                "1.1.1.1\n8.8.8.8\nexample.com:443",
            ),
            Field("port", "Default port", "number", 80, required=False),
            Field("timeout", "Timeout (s)", "number", 2.0, required=False),
        ],
    )
)
