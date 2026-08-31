"""Tool registry for the web panel.

Every module in this package that calls :func:`register` at import time adds one
tool to the panel. :func:`load_tools` imports them all on first use, so adding a
capability is just adding a file here -- nothing else needs editing.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, List

from .base import DEFAULT_CATEGORY, Field, Result, Tool

__all__ = ["Field", "Result", "Tool", "register", "load_tools", "get_tool"]

# Categories render in this order; anything else follows, alphabetically.
CATEGORY_ORDER = [DEFAULT_CATEGORY, "Network monitoring", "Device monitoring"]

_REGISTRY: "Dict[str, Tool]" = {}
_LOADED = False


def _sort_key(tool: Tool):
    try:
        category_rank = CATEGORY_ORDER.index(tool.category)
    except ValueError:
        category_rank = len(CATEGORY_ORDER)
    return (category_rank, tool.category.lower(), tool.title.lower())


def register(tool: Tool) -> Tool:
    """Add ``tool`` to the registry. Raises on a duplicate name."""
    if tool.name in _REGISTRY:
        raise ValueError(f"duplicate tool name: {tool.name!r}")
    _REGISTRY[tool.name] = tool
    return tool


#: modules skipped at load time because an optional dependency is missing
UNAVAILABLE: "Dict[str, str]" = {}


def load_tools() -> List[Tool]:
    """Import every sibling module once, then return the registered tools.

    A module whose optional dependency is missing (``ImportError``) is skipped
    and recorded in :data:`UNAVAILABLE` rather than breaking the whole panel.
    """
    global _LOADED
    if not _LOADED:
        for info in pkgutil.iter_modules(__path__):
            if info.name == "base" or info.name.startswith("_"):
                continue
            try:
                importlib.import_module(f"{__name__}.{info.name}")
            except ImportError as exc:
                UNAVAILABLE[info.name] = str(exc)
        _LOADED = True
    return sorted(_REGISTRY.values(), key=_sort_key)


def get_tool(name: str) -> "Tool | None":
    load_tools()
    return _REGISTRY.get(name)
