"""Panel module (device monitoring): FortiGate SD-WAN / link health."""

from __future__ import annotations

from typing import Dict

from ..fortigate import FortiGate, FortiGateError
from ._util import truthy
from . import Field, Result, Tool, register


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    token = (params.get("token") or "").strip()
    if not host or not token:
        raise ValueError("host and API token are required")
    verify = truthy(params.get("verify"))
    timeout = float(params.get("timeout") or 10.0)

    fg = FortiGate(host, token, verify=verify, timeout=timeout)
    try:
        data = fg.get("/api/v2/monitor/virtual-wan/health-check")
    except FortiGateError as exc:
        raise ValueError(str(exc))

    results = data.get("results") or {}
    rows = []
    alive = 0
    total = 0
    # results: { "<sla-name>": { "<member-iface>": {...} , ... }, ... }
    for check_name, members in results.items():
        if not isinstance(members, dict):
            continue
        for iface, stats in members.items():
            if not isinstance(stats, dict):
                continue
            total += 1
            status = stats.get("status", "?")
            if status == "up":
                alive += 1
            rows.append([
                check_name,
                iface,
                status,
                f"{stats.get('latency', 0):.1f}",
                f"{stats.get('jitter', 0):.1f}",
                f"{stats.get('packet_loss', 0):.1f}%",
            ])

    if not rows:
        raise ValueError("no SD-WAN health-check data (is SD-WAN configured?)")

    rows.sort(key=lambda r: (r[2] != "up", r[0], r[1]))
    return Result(
        columns=["sla", "member", "status", "latency ms", "jitter ms", "loss"],
        rows=rows,
        summary=f"{alive}/{total} WAN member(s) up on {host}",
        level="ok" if alive == total else "warn" if alive else "error",
    )


register(
    Tool(
        name="fortigate-wan",
        title="FortiGate WAN health",
        description="SD-WAN health-check status, latency, jitter and loss per WAN link.",
        category="Device monitoring",
        run=_run,
        fields=[
            Field("host", "FortiGate host", "text", "", "10.0.0.254"),
            Field("token", "API token", "password", "", "REST API admin token"),
            Field("verify", "Verify TLS cert (1/0)", "text", "0", required=False),
            Field("timeout", "Timeout (s)", "number", 10.0, required=False),
        ],
    )
)
