"""Panel module: WHOIS lookup over TCP port 43."""

from __future__ import annotations

import re
import socket
from typing import Dict

from . import Field, Result, Tool, register

_IANA = "whois.iana.org"
_REFERRAL = re.compile(r"^(?:refer|whois|ReferralServer):\s*(?:whois://)?([\w.-]+)", re.I | re.M)
_KEYS = (
    "Domain Name",
    "Registrar",
    "Creation Date",
    "Registry Expiry Date",
    "Updated Date",
    "Domain Status",
    "Name Server",
    "org-name",
    "OrgName",
    "netname",
    "NetName",
    "country",
    "Country",
    "CIDR",
    "inetnum",
)


def _ask(server: str, query: str, timeout: float) -> str:
    chunks = []
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("ascii", "ignore"))
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _run(params: Dict[str, str]) -> Result:
    target = (params.get("target") or "").strip()
    if not target:
        raise ValueError("target is required")
    timeout = float(params.get("timeout") or 5.0)

    try:
        root = _ask(_IANA, target, timeout)
        referral = _REFERRAL.search(root)
        server = referral.group(1) if referral else _IANA
        body = _ask(server, target, timeout) if server != _IANA else root
    except OSError as exc:
        raise ValueError(f"WHOIS lookup failed: {exc}")

    rows = []
    seen = set()
    for line in body.splitlines():
        if ":" not in line or line.lstrip().startswith(("%", "#")):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if value and any(key.lower() == k.lower() for k in _KEYS):
            item = (key, value)
            if item not in seen:
                seen.add(item)
                rows.append([key, value])

    if not rows:
        rows = [["raw", body.strip()[:2000] or "(empty response)"]]
    return Result(
        columns=["field", "value"],
        rows=rows,
        summary=f"WHOIS for {target} via {server}",
    )


register(
    Tool(
        name="whois",
        title="WHOIS",
        description="Look up registration details for a domain or IP (port 43).",
        run=_run,
        fields=[
            Field("target", "Domain or IP", "text", "", "example.com"),
            Field("timeout", "Timeout (s)", "number", 5.0, required=False),
        ],
    )
)
