"""Panel module (device monitoring): FortiGate interface / WAN status."""

from __future__ import annotations

from typing import Dict

from ..fortigate import FortiGate, FortiGateError
from ._util import human_bytes, truthy
from . import Field, Result, Tool, register


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    token = (params.get("token") or "").strip()
    if not host or not token:
        raise ValueError("host and API token are required")
    verify = truthy(params.get("verify"))
    only_up = truthy(params.get("physical_only"))
    timeout = float(params.get("timeout") or 10.0)

    fg = FortiGate(host, token, verify=verify, timeout=timeout)
    try:
        data = fg.get("/api/v2/monitor/system/interface", {"include_vlan": "true"})
    except FortiGateError as exc:
        raise ValueError(str(exc))

    results = data.get("results") or {}
    if isinstance(results, dict):
        items = results.items()
    else:  # some builds return a list
        items = ((r.get("name", "?"), r) for r in results)

    rows = []
    up = 0
    for name, info in items:
        if only_up and info.get("type") not in (None, "physical"):
            continue
        link = "up" if info.get("link") else "down"
        if link == "up":
            up += 1
        speed = info.get("speed")
        rows.append([
            name,
            link,
            f"{speed:g} Mbps" if isinstance(speed, (int, float)) and speed else "-",
            info.get("ip") or "-",
            human_bytes(info.get("rx_bytes", 0)),
            human_bytes(info.get("tx_bytes", 0)),
            f"{info.get('rx_errors', 0)}/{info.get('tx_errors', 0)}",
        ])

    rows.sort(key=lambda r: (r[1] != "up", r[0]))
    return Result(
        columns=["interface", "link", "speed", "ip", "rx", "tx", "err rx/tx"],
        rows=rows,
        summary=f"{up}/{len(rows)} interface(s) up on {host}",
        level="ok" if up else "warn",
    )


register(
    Tool(
        name="fortigate-interfaces",
        title="FortiGate interfaces",
        description="Link state, speed, address and counters for every FortiGate interface.",
        category="Device monitoring",
        run=_run,
        fields=[
            Field("host", "FortiGate host", "text", "", "10.0.0.254"),
            Field("token", "API token", "password", "", "REST API admin token"),
            Field("physical_only", "Physical only (1/0)", "text", "0", required=False),
            Field("verify", "Verify TLS cert (1/0)", "text", "0", required=False),
            Field("timeout", "Timeout (s)", "number", 10.0, required=False),
        ],
    )
)
