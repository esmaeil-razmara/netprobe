"""Tool registry for the web panel.

Every module in this package that calls :func:`register` at import time adds one
tool to the panel. :func:`load_tools` imports them all on first use, so adding a
capability is just adding a file here -- nothing else needs editing.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, List

from .base import Field, Result, Tool

__all__ = ["Field", "Result", "Tool", "register", "load_tools", "get_tool"]

_REGISTRY: "Dict[str, Tool]" = {}
_LOADED = False


def register(tool: Tool) -> Tool:
    """Add ``tool`` to the registry. Raises on a duplicate name."""
    if tool.name in _REGISTRY:
        raise ValueError(f"duplicate tool name: {tool.name!r}")
    _REGISTRY[tool.name] = tool
    return tool


def load_tools() -> List[Tool]:
    """Import every sibling module once, then return the registered tools."""
    global _LOADED
    if not _LOADED:
        for info in pkgutil.iter_modules(__path__):
            if info.name != "base":
                importlib.import_module(f"{__name__}.{info.name}")
        _LOADED = True
    return sorted(_REGISTRY.values(), key=lambda t: t.title.lower())


def get_tool(name: str) -> "Tool | None":
    load_tools()
    return _REGISTRY.get(name)
