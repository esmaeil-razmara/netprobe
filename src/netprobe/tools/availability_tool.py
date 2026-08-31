"""Panel module (monitoring): sample an endpoint over a short window."""

from __future__ import annotations

from typing import Dict

from ..scanner import monitor_endpoint
from . import Field, Result, Tool, register


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    port = int(params.get("port") or 443)
    duration = float(params.get("duration") or 20.0)
    interval = float(params.get("interval") or 4.0)
    timeout = float(params.get("timeout") or 3.0)
    if not 1 <= duration <= 120:
        raise ValueError("duration must be between 1 and 120 seconds")
    if not 0.1 <= interval <= 60:
        raise ValueError("interval must be between 0.1 and 60 seconds")

    samples = monitor_endpoint(host, port, duration, interval, timeout=timeout)
    rows = [
        [f"{elapsed:.1f}s", f"{latency} ms" if latency is not None else "DOWN"]
        for elapsed, latency in samples
    ]
    up = [latency for _e, latency in samples if latency is not None]
    pct = 100.0 * len(up) / len(samples)
    if up:
        stats = f"min {min(up)} / avg {round(sum(up) / len(up), 2)} / max {max(up)} ms"
    else:
        stats = "no successful connections"
    level = "ok" if pct == 100 else "warn" if pct >= 50 else "error"

    return Result(
        columns=["at", "rtt"],
        rows=rows,
        summary=f"{host}:{port} -- {pct:.0f}% up over {len(samples)} sample(s), {stats}",
        level=level,
    )


register(
    Tool(
        name="availability",
        title="Availability",
        description="Repeatedly probe one host:port over a time window and report uptime.",
        category="Network monitoring",
        run=_run,
        fields=[
            Field("host", "Host", "text", "", "example.com"),
            Field("port", "Port", "number", 443),
            Field("duration", "Duration (s)", "number", 20, required=False),
            Field("interval", "Interval (s)", "number", 4, required=False),
            Field("timeout", "Timeout (s)", "number", 3.0, required=False),
        ],
    )
)
