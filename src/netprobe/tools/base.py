"""Data model shared by every panel tool (module)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class Field:
    """One input rendered as a form control in the web panel."""

    name: str
    label: str
    type: str = "text"  # "text" | "number" | "textarea"
    default: Any = ""
    placeholder: str = ""
    required: bool = True
    help: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "type": self.type,
            "default": self.default,
            "placeholder": self.placeholder,
            "required": self.required,
            "help": self.help,
        }


@dataclass(frozen=True)
class Result:
    """A tool's output: a table plus a one-line summary.

    ``level`` is a hint for the panel: ``"ok"``, ``"warn"`` or ``"error"``
    (the run still succeeded -- it just colours the summary).
    """

    columns: List[str]
    rows: List[List[Any]]
    summary: str = ""
    level: str = "ok"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "columns": self.columns,
            "rows": self.rows,
            "summary": self.summary,
            "level": self.level,
        }


DEFAULT_CATEGORY = "Network tools"


@dataclass(frozen=True)
class Tool:
    """A self-contained panel module.

    Add a new capability by dropping a file in ``netprobe/tools/`` that builds a
    ``Tool`` and passes it to :func:`netprobe.tools.register`. ``category`` is the
    heading the panel groups it under in the sidebar.
    """

    name: str
    title: str
    description: str
    run: Callable[[Dict[str, str]], Result]
    fields: List[Field] = field(default_factory=list)
    category: str = DEFAULT_CATEGORY

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "fields": [f.to_dict() for f in self.fields],
        }
