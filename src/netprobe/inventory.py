"""A tiny JSON-file device inventory for the panel.

Saved so you don't retype switch addresses (and, optionally, their read-only
SNMP community). The file lives at ``~/.netprobe/devices.json`` unless
``NETPROBE_DATA`` or ``netprobe serve --data-dir`` points elsewhere.

The file may hold credentials in plain text -- it is written with 0600
permissions and is meant for a single-user machine.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional

_VALID_KINDS = ("cisco", "fortigate", "other")


@dataclass
class Device:
    host: str
    name: str = ""
    kind: str = "other"
    community: str = ""
    username: str = ""
    notes: str = ""
    added: str = ""

    def public(self) -> Dict[str, object]:
        """As a dict, with the community replaced by a boolean flag."""
        data = asdict(self)
        data["has_community"] = bool(self.community)
        data.pop("community", None)
        return data


def default_path() -> Path:
    base = os.environ.get("NETPROBE_DATA")
    root = Path(base) if base else Path.home() / ".netprobe"
    return root / "devices.json"


class Inventory:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else default_path()
        self._lock = Lock()

    # -- storage -------------------------------------------------------
    def _read(self) -> List[dict]:
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except FileNotFoundError:
            return []
        except (ValueError, OSError):
            return []
        return raw if isinstance(raw, list) else []

    def _write(self, items: List[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(items, handle, indent=2)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- operations --------------------------------------------------
    def list(self) -> List[Device]:
        return [Device(**{k: d.get(k, "") for k in Device.__dataclass_fields__}) for d in self._read()]

    def get(self, host: str) -> Optional[Device]:
        for device in self.list():
            if device.host == host:
                return device
        return None

    def upsert(self, device: Device) -> Device:
        if not device.host:
            raise ValueError("host is required")
        if device.kind not in _VALID_KINDS:
            device.kind = "other"
        if not device.added:
            device.added = date.today().isoformat()
        with self._lock:
            items = self._read()
            for i, existing in enumerate(items):
                if existing.get("host") == device.host:
                    merged = {**existing, **asdict(device)}
                    # keep an existing community if the new one is blank
                    if not device.community and existing.get("community"):
                        merged["community"] = existing["community"]
                    items[i] = merged
                    break
            else:
                items.append(asdict(device))
            self._write(items)
        return device

    def remove(self, host: str) -> bool:
        with self._lock:
            items = self._read()
            kept = [d for d in items if d.get("host") != host]
            if len(kept) == len(items):
                return False
            self._write(kept)
            return True


_override: Optional[Path] = None
_cached: Optional[Inventory] = None


def set_data_dir(path: Optional[str]) -> None:
    """Point the shared inventory at ``<path>/devices.json`` (or reset with None)."""
    global _override, _cached
    _override = Path(path) / "devices.json" if path else None
    _cached = None


def get_inventory() -> Inventory:
    """The process-wide inventory used by the server and the device tools."""
    global _cached
    if _cached is None:
        _cached = Inventory(_override or default_path())
    return _cached
