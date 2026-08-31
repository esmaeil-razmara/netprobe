"""Panel module (device monitoring): interface inventory via SNMP."""

from __future__ import annotations

from typing import Dict

from ..snmp import SNMPError, walk
from . import Field, Result, Tool, register

# column OID -> short key
_COLUMNS = {
    "1.3.6.1.2.1.2.2.1.2": "descr",          # ifDescr
    "1.3.6.1.2.1.2.2.1.7": "admin",          # ifAdminStatus
    "1.3.6.1.2.1.2.2.1.8": "oper",           # ifOperStatus
    "1.3.6.1.2.1.31.1.1.1.15": "speed_mbps",  # ifHighSpeed
    "1.3.6.1.2.1.31.1.1.1.18": "alias",       # ifAlias
}
_ADMIN = {1: "up", 2: "down", 3: "testing"}
_OPER = {
    1: "up", 2: "down", 3: "testing", 4: "unknown",
    5: "dormant", 6: "notPresent", 7: "lowerLayerDown",
}


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    community = (params.get("community") or "").strip()
    if not community:
        raise ValueError("community string is required")
    timeout = float(params.get("timeout") or 2.0)

    by_index: Dict[str, Dict[str, object]] = {}
    try:
        for base, key in _COLUMNS.items():
            for oid, value in walk(host, community, base, timeout=timeout):
                index = oid[len(base) + 1:]
                by_index.setdefault(index, {})[key] = value
    except SNMPError as exc:
        raise ValueError(str(exc))

    if not by_index:
        raise ValueError("no interface data (wrong community, or SNMP not enabled?)")

    def sort_key(idx: str):
        try:
            return [int(p) for p in idx.split(".")]
        except ValueError:
            return [1 << 30]

    rows = []
    up = 0
    for index in sorted(by_index, key=sort_key):
        row = by_index[index]
        admin = _ADMIN.get(row.get("admin"), row.get("admin"))
        oper = _OPER.get(row.get("oper"), row.get("oper"))
        if oper == "up":
            up += 1
        speed = row.get("speed_mbps")
        name = row.get("descr") or row.get("alias") or "?"
        rows.append([
            index,
            name,
            admin,
            oper,
            f"{speed} Mbps" if speed else "-",
        ])

    return Result(
        columns=["#", "interface", "admin", "oper", "speed"],
        rows=rows,
        summary=f"{up}/{len(rows)} interface(s) up on {host}",
        level="ok" if up else "warn",
    )


register(
    Tool(
        name="snmp-interfaces",
        title="Cisco interfaces (SNMP)",
        description="Walk IF-MIB over SNMP v2c for admin/oper status and speed.",
        category="Device monitoring",
        run=_run,
        fields=[
            Field("host", "Switch / router IP", "text", "", "10.0.0.1"),
            Field("community", "SNMP community", "password", "", "read-only community"),
            Field("timeout", "Timeout (s)", "number", 2.0, required=False),
        ],
    )
)
