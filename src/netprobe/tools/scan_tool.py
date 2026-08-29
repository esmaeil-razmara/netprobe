"""Panel module: TCP connect scan of one host."""

from __future__ import annotations

from typing import Dict

from ..scanner import parse_ports, scan_ports
from . import Field, Result, Tool, register


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    ports = parse_ports(params.get("ports") or "1-1024")
    timeout = float(params.get("timeout") or 1.0)

    results = scan_ports(host, ports, timeout=timeout)
    open_ports = [r for r in results if r.is_open]
    return Result(
        columns=["port", "state"],
        rows=[[r.port, "open"] for r in open_ports],
        summary=f"{len(open_ports)}/{len(results)} port(s) open on {host}",
    )


register(
    Tool(
        name="scan",
        title="Port scan",
        description="TCP connect scan of a single host across a set of ports.",
        run=_run,
        fields=[
            Field("host", "Host", "text", "", "example.com or 10.0.0.5"),
            Field("ports", "Ports", "text", "1-1024", "22,80,8000-8010"),
            Field("timeout", "Timeout (s)", "number", 1.0, required=False),
        ],
    )
)
