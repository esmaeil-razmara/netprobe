"""Panel module (device monitoring): run one read-only command over SSH."""

from __future__ import annotations

from typing import Dict

from ..cisco_ssh import CiscoSSHError, is_read_only, run_commands
from ._util import resolve_username, truthy
from . import Field, Result, Tool, register


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    username = resolve_username(params, host)
    password = params.get("password") or ""
    if not password:
        raise ValueError("password is required")
    command = (params.get("command") or "").strip()
    if not command:
        raise ValueError("command is required")
    if not is_read_only(command):
        raise ValueError("only read-only commands are allowed (show / display / dir / ping / traceroute)")

    device_type = (params.get("device_type") or "cisco_ios").strip()
    secret = params.get("secret") or ""
    port = int(params.get("port") or 22)
    parse = truthy(params.get("parse"))

    try:
        output = run_commands(
            host, username, password, [command],
            device_type=device_type, port=port, secret=secret, use_textfsm=parse,
        )[command]
    except CiscoSSHError as exc:
        raise ValueError(str(exc))

    if isinstance(output, list) and output and isinstance(output[0], dict):
        columns = list(output[0].keys())
        rows = [[str(row.get(col, "")) for col in columns] for row in output]
        return Result(columns, rows, f"{command}: {len(rows)} row(s) from {host}")

    lines = str(output).splitlines() or ["(no output)"]
    return Result(
        columns=["output"],
        rows=[[line] for line in lines],
        summary=f"{command} on {host} -- {len(lines)} line(s)",
    )


register(
    Tool(
        name="cisco-command",
        title="Cisco command (SSH)",
        description="Run a single read-only show/display command on a device over SSH.",
        category="Device monitoring",
        run=_run,
        fields=[
            Field("host", "Host", "text", "", "10.0.0.1"),
            Field("username", "Username", "text", "", required=False),
            Field("password", "Password", "password", ""),
            Field("secret", "Enable secret", "password", "", required=False),
            Field("command", "Command", "text", "show version", placeholder="show ip interface brief"),
            Field("device_type", "Device type", "text", "cisco_ios", required=False),
            Field("parse", "Parse with TextFSM (1/0)", "text", "0", required=False),
            Field("port", "SSH port", "number", 22, required=False),
        ],
    )
)
