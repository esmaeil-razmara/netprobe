"""Small formatting helpers shared by the device tools."""

from __future__ import annotations


def human_bytes(value: float) -> str:
    value = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TB"


def human_bps(bits_per_second: float) -> str:
    value = float(bits_per_second)
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if value < 1000 or unit == "Gbps":
            return f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} Gbps"


def truthy(value: object) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def resolve_community(params: dict, host: str) -> str:
    """Community string from the form, or the one saved with ``host``."""
    community = (params.get("community") or "").strip()
    if community:
        return community
    from ..inventory import get_inventory

    device = get_inventory().get(host)
    if device and device.community:
        return device.community
    raise ValueError("community string is required (or save it with the device)")
