"""Panel module: forward and reverse DNS resolution."""

from __future__ import annotations

import ipaddress
import socket
from typing import Dict

from . import Field, Result, Tool, register


def _run(params: Dict[str, str]) -> Result:
    target = (params.get("target") or "").strip()
    if not target:
        raise ValueError("target is required")

    rows = []
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        try:
            host, aliases, _ = socket.gethostbyaddr(target)
        except OSError as exc:
            raise ValueError(f"reverse lookup failed: {exc}")
        rows.append(["PTR", host])
        rows.extend(["alias", name] for name in aliases)
    else:
        try:
            infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            raise ValueError(f"lookup failed: {exc}")
        seen = set()
        for family, _t, _p, _c, sockaddr in infos:
            addr = sockaddr[0]
            if addr in seen:
                continue
            seen.add(addr)
            rows.append(["A" if family == socket.AF_INET else "AAAA", addr])

    return Result(
        columns=["type", "value"],
        rows=rows,
        summary=f"{len(rows)} record(s) for {target}",
    )


register(
    Tool(
        name="dns",
        title="DNS lookup",
        description="Resolve a hostname to addresses, or an address back to a name.",
        run=_run,
        fields=[
            Field("target", "Host or IP", "text", "", "example.com or 1.1.1.1"),
        ],
    )
)
