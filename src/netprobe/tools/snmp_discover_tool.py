"""Panel module (device monitoring): find SNMP devices in an address range."""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from ..inventory import Device, get_inventory
from ..snmp import SNMPError, get
from ._util import truthy
from . import Field, Result, Tool, register

_SYS_NAME = "1.3.6.1.2.1.1.5.0"
_SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def _hosts(spec: str) -> List[str]:
    spec = spec.strip()
    if "/" in spec:
        return [str(ip) for ip in ipaddress.ip_network(spec, strict=False).hosts()]
    if "-" in spec:
        start_s, end_s = (p.strip() for p in spec.split("-", 1))
        if "." not in end_s:  # shorthand "10.0.0.1-20"
            end_s = start_s.rsplit(".", 1)[0] + "." + end_s
        start, end = ipaddress.ip_address(start_s), ipaddress.ip_address(end_s)
        if int(end) < int(start) or int(end) - int(start) > 4096:
            raise ValueError("range is empty or larger than 4096 addresses")
        return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
    ipaddress.ip_address(spec)  # single host -> validate
    return [spec]


def _probe(host: str, community: str, timeout: float) -> Optional[Dict[str, str]]:
    try:
        values = get(host, community, [_SYS_NAME, _SYS_DESCR], timeout=timeout, retries=1)
    except SNMPError:
        return None
    descr = str(values.get(_SYS_DESCR, "") or "")
    return {
        "host": host,
        "name": str(values.get(_SYS_NAME, "") or ""),
        "descr": descr,
        "kind": "cisco" if "cisco" in descr.lower() else "other",
    }


def _run(params: Dict[str, str]) -> Result:
    community = (params.get("community") or "").strip()
    if not community:
        raise ValueError("community string is required")
    try:
        hosts = _hosts(params.get("range") or "")
    except ValueError as exc:
        raise ValueError(f"bad range: {exc}")
    if not hosts:
        raise ValueError("range is required")
    timeout = float(params.get("timeout") or 1.0)
    do_save = truthy(params.get("save"))

    with ThreadPoolExecutor(max_workers=min(64, len(hosts))) as pool:
        found = [d for d in pool.map(lambda h: _probe(h, community, timeout), hosts) if d]
    found.sort(key=lambda d: tuple(int(p) for p in d["host"].split(".")))

    saved = 0
    if do_save and found:
        inv = get_inventory()
        for dev in found:
            inv.upsert(Device(
                host=dev["host"],
                name=dev["name"],
                kind=dev["kind"],
                community=community,
                notes="discovered",
            ))
            saved += 1

    rows = [[d["host"], d["name"] or "-", d["kind"], d["descr"][:80] or "-"] for d in found]
    summary = f"{len(found)} device(s) responded out of {len(hosts)} probed"
    if do_save:
        summary += f"; saved {saved} to inventory"
    return Result(
        columns=["host", "sysName", "kind", "sysDescr"],
        rows=rows,
        summary=summary,
        level="ok" if found else "warn",
    )


register(
    Tool(
        name="snmp-discover",
        title="Discover devices (SNMP)",
        description="Sweep an address range for SNMP-speaking devices and optionally save them.",
        category="Device monitoring",
        run=_run,
        fields=[
            Field("range", "Range (CIDR or a.b.c.d-e)", "text", "", "10.0.0.0/24"),
            Field("community", "SNMP community", "password", "", "read-only community"),
            Field("save", "Save results to inventory (1/0)", "text", "1", required=False),
            Field("timeout", "Timeout (s)", "number", 1.0, required=False),
        ],
    )
)
