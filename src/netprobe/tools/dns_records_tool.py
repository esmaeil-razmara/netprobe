"""Panel module: query real DNS record types over UDP."""

from __future__ import annotations

from typing import Dict

from ..dns_query import DNSError, RECORD_TYPES, query
from . import Field, Result, Tool, register

_DEFAULT_TYPES = "A,AAAA,MX,TXT,NS"


def _run(params: Dict[str, str]) -> Result:
    name = (params.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")
    server = (params.get("server") or "1.1.1.1").strip()
    timeout = float(params.get("timeout") or 3.0)

    wanted = [t.strip().upper() for t in (params.get("types") or _DEFAULT_TYPES).split(",")]
    wanted = [t for t in wanted if t]
    unknown = [t for t in wanted if t not in RECORD_TYPES]
    if unknown:
        raise ValueError(f"unsupported record type(s): {', '.join(unknown)}")

    rows = []
    errors = []
    for rtype in wanted:
        try:
            for rec in query(name, rtype, server=server, timeout=timeout):
                rows.append([rec.rtype, rec.name, rec.value, rec.ttl])
        except DNSError as exc:
            errors.append(f"{rtype}: {exc}")

    if not rows and errors:
        raise ValueError("; ".join(errors))

    summary = f"{len(rows)} record(s) for {name} via {server}"
    if errors:
        summary += f"  ({len(errors)} type(s) failed)"
    return Result(
        columns=["type", "name", "value", "ttl"],
        rows=rows,
        summary=summary,
        level="warn" if errors else "ok",
    )


register(
    Tool(
        name="dns-records",
        title="DNS records",
        description="Query A / AAAA / MX / TXT / NS / CNAME / SOA / PTR from a resolver.",
        run=_run,
        fields=[
            Field("name", "Name", "text", "", "example.com"),
            Field("types", "Record types", "text", _DEFAULT_TYPES, required=False),
            Field("server", "Resolver", "text", "1.1.1.1", required=False),
            Field("timeout", "Timeout (s)", "number", 3.0, required=False),
        ],
    )
)
