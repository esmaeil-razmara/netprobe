"""Panel module (device monitoring): manage the saved device inventory."""

from __future__ import annotations

from typing import Dict

from ..inventory import Device, get_inventory
from . import Field, Result, Tool, register


def _table(summary: str, level: str = "ok") -> Result:
    devices = get_inventory().list()
    rows = [
        [d.host, d.name or "-", d.kind, "yes" if d.community else "no", d.notes or "-"]
        for d in devices
    ]
    return Result(
        columns=["host", "name", "kind", "community saved", "notes"],
        rows=rows,
        summary=summary or f"{len(rows)} saved device(s)",
        level=level,
    )


def _run(params: Dict[str, str]) -> Result:
    action = (params.get("action") or "list").strip().lower()
    host = (params.get("host") or "").strip()
    inv = get_inventory()

    if action == "list":
        return _table("")

    if action == "remove":
        if not host:
            raise ValueError("host is required to remove a device")
        removed = inv.remove(host)
        return _table(
            f"removed {host}" if removed else f"{host} was not in the inventory",
            level="ok" if removed else "warn",
        )

    if action in ("add", "save"):
        if not host:
            raise ValueError("host is required")
        inv.upsert(Device(
            host=host,
            name=(params.get("name") or "").strip(),
            kind=(params.get("kind") or "other").strip() or "other",
            community=params.get("community") or "",
            notes=(params.get("notes") or "").strip(),
        ))
        return _table(f"saved {host}")

    raise ValueError("action must be one of: list, add, remove")


register(
    Tool(
        name="devices",
        title="Saved devices",
        description="List, add or remove devices in the inventory the other tools read from.",
        category="Device monitoring",
        run=_run,
        fields=[
            Field("action", "Action (list / add / remove)", "text", "list", required=False),
            Field("host", "Host / IP", "text", "", "10.0.0.1", required=False),
            Field("name", "Name", "text", "", "core-switch", required=False),
            Field("kind", "Kind (cisco / fortigate / other)", "text", "cisco", required=False),
            Field("community", "SNMP community (stored)", "password", "", required=False),
            Field("notes", "Notes", "text", "", required=False),
        ],
    )
)
