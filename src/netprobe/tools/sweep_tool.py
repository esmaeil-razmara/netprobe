"""Panel module: find hosts in a subnet that accept a TCP connection."""

from __future__ import annotations

from typing import Dict

from ..scanner import sweep
from . import Field, Result, Tool, register


def _run(params: Dict[str, str]) -> Result:
    network = (params.get("network") or "").strip()
    if not network:
        raise ValueError("network is required")
    port = int(params.get("port") or 80)
    timeout = float(params.get("timeout") or 1.0)

    live = sweep(network, port, timeout=timeout)
    return Result(
        columns=["host", "port"],
        rows=[[host, port] for host in live],
        summary=f"{len(live)} host(s) responding on port {port} in {network}",
    )


register(
    Tool(
        name="sweep",
        title="Subnet sweep",
        description="Probe every host in a CIDR range for one open TCP port.",
        run=_run,
        fields=[
            Field("network", "Network (CIDR)", "text", "", "192.168.1.0/24"),
            Field("port", "Port", "number", 80),
            Field("timeout", "Timeout (s)", "number", 1.0, required=False),
        ],
    )
)
