"""Panel module (device monitoring): the MAC address-table over SSH."""

from __future__ import annotations

from typing import Dict

from ..cisco_ssh import CiscoSSHError, run_commands
from ._util import resolve_username
from . import Field, Result, Tool, register

_CMD = "show mac address-table"


def _first(record: dict, *keys):
    for key in keys:
        if record.get(key):
            value = record[key]
            return ", ".join(value) if isinstance(value, list) else str(value)
    return ""


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

    try:
        output = run_commands(
            host, username, password, [_CMD],
            device_type=device_type, port=port, secret=secret, use_textfsm=True,
        )[_CMD]
    except CiscoSSHError as exc:
        raise ValueError(str(exc))

    if not isinstance(output, list):
        lines = str(output).splitlines() or ["(no output)"]
        return Result(["output"], [[line] for line in lines],
                      f"{len(lines)} line(s) (could not parse) from {host}", level="warn")

    rows = []
    for record in output:
        rows.append([
            _first(record, "vlan", "VLAN"),
            _first(record, "destination_address", "mac", "MAC_ADDRESS", "mac_address"),
            _first(record, "type", "TYPE"),
            _first(record, "destination_port", "ports", "PORTS", "port"),
        ])
    return Result(
        columns=["vlan", "mac", "type", "port"],
        rows=rows,
        summary=f"{len(rows)} MAC entr{'y' if len(rows) == 1 else 'ies'} on {host}",
    )


register(
    Tool(
        name="cisco-mac-table",
        title="Cisco MAC table (SSH)",
        description="Read the switch MAC address-table and show VLAN / MAC / port.",
        category="Device monitoring",
        run=_run,
        fields=[
            Field("host", "Host", "text", "", "10.0.0.1"),
            Field("username", "Username", "text", "", required=False),
            Field("password", "Password", "password", ""),
            Field("secret", "Enable secret", "password", "", required=False),
            Field("device_type", "Device type", "text", "cisco_ios", required=False),
            Field("port", "SSH port", "number", 22, required=False),
        ],
    )
)
