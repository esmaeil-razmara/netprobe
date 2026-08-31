"""Panel module: subnet calculator (no network access)."""

from __future__ import annotations

import ipaddress
from typing import Dict

from . import Field, Result, Tool, register


def _run(params: Dict[str, str]) -> Result:
    value = (params.get("cidr") or "").strip()
    if not value:
        raise ValueError("cidr is required")
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(str(exc))

    hosts = list(net.hosts())
    rows = [
        ["network", str(net.network_address)],
        ["prefix length", str(net.prefixlen)],
        ["netmask", str(net.netmask)],
        ["wildcard", str(net.hostmask)],
        ["broadcast", str(net.broadcast_address) if net.version == 4 else "n/a"],
        ["total addresses", str(net.num_addresses)],
        ["usable hosts", str(len(hosts))],
        ["first host", str(hosts[0]) if hosts else "n/a"],
        ["last host", str(hosts[-1]) if hosts else "n/a"],
        ["is private", str(net.is_private)],
    ]
    return Result(
        columns=["field", "value"],
        rows=rows,
        summary=f"{net} -- {len(hosts)} usable host(s)",
    )


register(
    Tool(
        name="subnet",
        title="Subnet calculator",
        description="Break a CIDR block down into mask, range and host count.",
        run=_run,
        fields=[
            Field("cidr", "CIDR", "text", "", "192.168.1.0/24 or 10.0.0.5/22"),
        ],
    )
)
