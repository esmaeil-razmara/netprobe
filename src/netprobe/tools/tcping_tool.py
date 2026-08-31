"""Panel module: measure TCP handshake latency to a host:port."""

from __future__ import annotations

from typing import Dict

from ..scanner import tcp_latency
from . import Field, Result, Tool, register


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    port = int(params.get("port") or 443)
    count = int(params.get("count") or 4)
    if not 1 <= count <= 50:
        raise ValueError("count must be between 1 and 50")
    timeout = float(params.get("timeout") or 2.0)

    samples = tcp_latency(host, port, count=count, timeout=timeout)
    rows = [
        [str(i), f"{ms} ms" if ms is not None else "timeout"]
        for i, ms in enumerate(samples, start=1)
    ]
    ok = [ms for ms in samples if ms is not None]
    if ok:
        stats = f"min {min(ok)} / avg {round(sum(ok) / len(ok), 2)} / max {max(ok)} ms"
        level = "ok"
    else:
        stats = "no successful connections"
        level = "error"

    return Result(
        columns=["#", "rtt"],
        rows=rows,
        summary=f"{len(ok)}/{len(samples)} ok -- {stats}",
        level=level,
    )


register(
    Tool(
        name="tcping",
        title="TCP ping",
        description="Repeatedly time the TCP handshake to a host and port.",
        run=_run,
        fields=[
            Field("host", "Host", "text", "", "example.com"),
            Field("port", "Port", "number", 443),
            Field("count", "Count", "number", 4, required=False),
            Field("timeout", "Timeout (s)", "number", 2.0, required=False),
        ],
    )
)
