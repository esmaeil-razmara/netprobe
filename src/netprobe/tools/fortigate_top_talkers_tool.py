"""Panel module (device monitoring): FortiGate top source IPs by traffic."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict

from ..fortigate import FortiGate, FortiGateError
from ._util import human_bytes, truthy
from . import Field, Result, Tool, register

# session field names vary between FortiOS versions
_SRC_KEYS = ("source", "src", "srcip", "src_addr")
_BYTE_KEYS = ("bytes", "total_bytes")


def _session_bytes(session: dict) -> int:
    for key in _BYTE_KEYS:
        if key in session:
            return int(session[key] or 0)
    return int(session.get("rx_bytes", 0) or 0) + int(session.get("tx_bytes", 0) or 0)


def _session_src(session: dict) -> str:
    for key in _SRC_KEYS:
        if session.get(key):
            return str(session[key])
    return "?"


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    token = (params.get("token") or "").strip()
    if not host or not token:
        raise ValueError("host and API token are required")
    verify = truthy(params.get("verify"))
    top_n = int(params.get("top") or 15)
    count = max(100, min(int(params.get("scan") or 2000), 10000))
    timeout = float(params.get("timeout") or 15.0)

    fg = FortiGate(host, token, verify=verify, timeout=timeout)
    try:
        data = fg.get(
            "/api/v2/monitor/firewall/session",
            {"count": count, "summary": "false", "ip_version": "ipv4"},
        )
    except FortiGateError as exc:
        raise ValueError(str(exc))

    sessions = data.get("results") or []
    if not sessions:
        raise ValueError("no active sessions returned")

    by_src_bytes: Dict[str, int] = defaultdict(int)
    by_src_count: Dict[str, int] = defaultdict(int)
    for session in sessions:
        src = _session_src(session)
        by_src_bytes[src] += _session_bytes(session)
        by_src_count[src] += 1

    ranked = sorted(by_src_bytes.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    has_bytes = any(b for _s, b in ranked)
    rows = [
        [src, human_bytes(total) if has_bytes else "n/a", by_src_count[src]]
        for src, total in ranked
    ]

    summary = f"top {len(rows)} source(s) across {len(sessions)} session(s) on {host}"
    if not has_bytes:
        summary += " -- this FortiOS build's session list has no byte counters"
    return Result(
        columns=["source", "bytes", "sessions"],
        rows=rows,
        summary=summary,
        level="ok" if has_bytes else "warn",
    )


register(
    Tool(
        name="fortigate-top-talkers",
        title="FortiGate top talkers",
        description="Aggregate active firewall sessions by source IP to find the heaviest users.",
        category="Device monitoring",
        run=_run,
        fields=[
            Field("host", "FortiGate host", "text", "", "10.0.0.254"),
            Field("token", "API token", "password", "", "REST API admin token"),
            Field("top", "Show top N", "number", 15, required=False),
            Field("scan", "Sessions to scan", "number", 2000, required=False),
            Field("verify", "Verify TLS cert (1/0)", "text", "0", required=False),
            Field("timeout", "Timeout (s)", "number", 15.0, required=False),
        ],
    )
)
