"""Panel module (device monitoring): per-interface throughput via SNMP counters."""

from __future__ import annotations

import time
from typing import Dict, Tuple

from ..snmp import SNMPError, walk
from ._util import human_bps
from . import Field, Result, Tool, register

_DESCR = "1.3.6.1.2.1.2.2.1.2"
_SPEED = "1.3.6.1.2.1.31.1.1.1.15"          # ifHighSpeed (Mbps)
_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"           # ifHCInOctets (64-bit)
_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"         # ifHCOutOctets (64-bit)
_IN32 = "1.3.6.1.2.1.2.2.1.10"              # ifInOctets (32-bit fallback)
_OUT32 = "1.3.6.1.2.1.2.2.1.16"             # ifOutOctets


def _column(host, community, base, timeout) -> Dict[str, int]:
    return {
        oid[len(base) + 1:]: value
        for oid, value in walk(host, community, base, timeout=timeout)
        if isinstance(value, int)
    }


def _sample(host, community, timeout) -> Tuple[Dict[str, Tuple[int, int]], float, int]:
    ins = _column(host, community, _HC_IN, timeout)
    outs = _column(host, community, _HC_OUT, timeout)
    width = 64
    if not ins:
        ins = _column(host, community, _IN32, timeout)
        outs = _column(host, community, _OUT32, timeout)
        width = 32
    now = time.monotonic()
    return {i: (ins[i], outs.get(i, 0)) for i in ins}, now, width


def _delta(new: int, old: int, width: int) -> int:
    d = new - old
    return d if d >= 0 else d + (1 << width)


def _run(params: Dict[str, str]) -> Result:
    host = (params.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    community = (params.get("community") or "").strip()
    if not community:
        raise ValueError("community string is required")
    interval = float(params.get("interval") or 10.0)
    timeout = float(params.get("timeout") or 2.0)
    if not 2 <= interval <= 120:
        raise ValueError("interval must be between 2 and 120 seconds")

    try:
        first, t0, width = _sample(host, community, timeout)
        if not first:
            raise ValueError("no interface counters (wrong community, or SNMP off?)")
        time.sleep(interval)
        second, t1, _ = _sample(host, community, timeout)
        descr = {o[len(_DESCR) + 1:]: v for o, v in walk(host, community, _DESCR, timeout=timeout)}
        speed = {o[len(_SPEED) + 1:]: v for o, v in walk(host, community, _SPEED, timeout=timeout)}
    except SNMPError as exc:
        raise ValueError(str(exc))

    elapsed = max(0.1, t1 - t0)
    rows = []
    for index, (in_now, out_now) in second.items():
        if index not in first:
            continue
        in_bps = _delta(in_now, first[index][0], width) * 8 / elapsed
        out_bps = _delta(out_now, first[index][1], width) * 8 / elapsed
        link_mbps = speed.get(index)
        util = ""
        if link_mbps:
            pct = max(in_bps, out_bps) / (link_mbps * 1_000_000) * 100
            util = f"{pct:.1f}%"
        rows.append([
            descr.get(index, index),
            human_bps(in_bps),
            human_bps(out_bps),
            util or "-",
            max(in_bps, out_bps),
        ])

    rows.sort(key=lambda r: r[-1], reverse=True)
    table = [r[:-1] for r in rows]
    return Result(
        columns=["interface", "in", "out", "utilisation"],
        rows=table,
        summary=f"{len(table)} interface(s) sampled over {elapsed:.0f}s on {host}",
    )


register(
    Tool(
        name="snmp-bandwidth",
        title="Cisco bandwidth (SNMP)",
        description="Read interface octet counters twice and report the throughput.",
        category="Device monitoring",
        run=_run,
        fields=[
            Field("host", "Switch / router IP", "text", "", "10.0.0.1"),
            Field("community", "SNMP community", "password", "", "read-only community"),
            Field("interval", "Sample gap (s)", "number", 10, required=False),
            Field("timeout", "Timeout (s)", "number", 2.0, required=False),
        ],
    )
)
