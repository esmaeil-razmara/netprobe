"""SSH access to Cisco-style devices via netmiko (optional dependency).

Importing this module requires ``netprobe[ssh]``. Only read-only commands are
allowed through -- this panel never changes device configuration.
"""

from __future__ import annotations

from typing import Dict, List, Union

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

#: command prefixes considered safe (non-configuring)
READ_ONLY_PREFIXES = ("show ", "show\t", "display ", "dir", "traceroute ", "ping ")

_DEVICE_TYPES = (
    "cisco_ios",
    "cisco_xe",
    "cisco_nxos",
    "cisco_xr",
    "cisco_asa",
    "arista_eos",
    "hp_procurve",
)


class CiscoSSHError(Exception):
    pass


def is_read_only(command: str) -> bool:
    c = command.strip().lower()
    return c in ("show", "dir") or c.startswith(READ_ONLY_PREFIXES)


def run_commands(
    host: str,
    username: str,
    password: str,
    commands: List[str],
    *,
    device_type: str = "cisco_ios",
    port: int = 22,
    secret: str = "",
    use_textfsm: bool = False,
    conn_timeout: float = 15.0,
    read_timeout: float = 30.0,
) -> Dict[str, Union[str, list]]:
    """Open one SSH session and run each read-only command."""
    if device_type not in _DEVICE_TYPES:
        raise CiscoSSHError(f"unsupported device_type: {device_type}")
    bad = [c for c in commands if not is_read_only(c)]
    if bad:
        raise CiscoSSHError(f"refusing non-read-only command(s): {', '.join(bad)}")

    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "conn_timeout": conn_timeout,
        "fast_cli": False,
    }
    if secret:
        params["secret"] = secret

    try:
        with ConnectHandler(**params) as conn:
            if secret:
                conn.enable()
            return {
                cmd: conn.send_command(cmd, use_textfsm=use_textfsm, read_timeout=read_timeout)
                for cmd in commands
            }
    except NetmikoAuthenticationException:
        raise CiscoSSHError("authentication failed (username / password / enable secret)")
    except NetmikoTimeoutException:
        raise CiscoSSHError(f"timed out connecting to {host}:{port}")
    except CiscoSSHError:
        raise
    except Exception as exc:  # netmiko raises a wide range of errors
        raise CiscoSSHError(f"{type(exc).__name__}: {exc}")
