"""Panel module (device monitoring): CDP/LLDP neighbours over SSH."""

from __future__ import annotations

from typing import Dict

from ..cisco_ssh import CiscoSSHError, run_commands
from ._util import resolve_username
from . import Field, Result, Tool, register

_CDP = "show cdp neighbors detail"
_LLDP = "show lldp neighbors detail"


def _first(record: dict, *keys):
    for key in keys:
        if record.get(key):
            value = record[key]
            return ", ".join(value) if isinstance(value, list) else str(value)
    return ""


def _rows(records):
    out = []
    for record in records:
        out.append([
            _first(record, "local_interface", "LOCAL_INTERFACE", "local_port"),
            _first(record, "neighbor_name", "NEIGHBOR_NAME", "neighbor", "chassis_id"),
            _first(record, "neighbor_interface", "NEIGHBOR_INTERFACE", "remote_port", "port_id"),
            _first(record, "platform", "PLATFORM", "system_description"),
            _first(record, "management_ip", "MANAGEMENT_IP", "mgmt_address"),
        ])
    return out


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    username = resolve_username(params, host)
    password = params.get("password") or ""
    if not password:
        raise ValueError("password is required")
    device_type = (params.get("device_type") or "cisco_ios").strip()
    secret = params.get("secret") or ""
    port = int(params.get("port") or 22)
    protocol = (params.get("protocol") or "cdp").strip().lower()
    command = _LLDP if protocol == "lldp" else _CDP

    try:
        output = run_commands(
            host, username, password, [command],
            device_type=device_type, port=port, secret=secret, use_textfsm=True,
        )[command]
    except CiscoSSHError as exc:
        raise ValueError(str(exc))

    if not isinstance(output, list):
        lines = str(output).splitlines() or ["(no output)"]
        return Result(["output"], [[line] for line in lines],
                      f"{len(lines)} line(s) (could not parse) from {host}", level="warn")

    rows = _rows(output)
    return Result(
        columns=["local if", "neighbor", "remote if", "platform", "mgmt ip"],
        rows=rows,
        summary=f"{len(rows)} {protocol.upper()} neighbour(s) of {host}",
        level="ok" if rows else "warn",
    )


register(
    Tool(
        name="cisco-neighbors",
        title="Cisco neighbors (SSH)",
        description="List CDP (or LLDP) neighbours to sketch the topology around a device.",
        category="Device monitoring",
        run=_run,
        fields=[
            Field("host", "Host", "text", "", "10.0.0.1"),
            Field("username", "Username", "text", "", required=False),
            Field("password", "Password", "password", ""),
            Field("secret", "Enable secret", "password", "", required=False),
            Field("protocol", "Protocol (cdp / lldp)", "text", "cdp", required=False),
            Field("device_type", "Device type", "text", "cisco_ios", required=False),
            Field("port", "SSH port", "number", 22, required=False),
        ],
    )
)
