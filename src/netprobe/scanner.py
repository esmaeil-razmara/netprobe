"""Core scanning helpers: parse port specs, TCP connect scan, subnet sweep."""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


@dataclass(frozen=True)
class PortResult:
    """Outcome of probing a single TCP port."""

    port: int
    is_open: bool


def parse_ports(spec: str) -> list[int]:
    """Turn a spec like ``"22,80,8000-8010"`` into a sorted list of ports.

    Raises ``ValueError`` on malformed input or ports outside 1-65535.
    """
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"range start after end: {chunk!r}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    if not ports:
        raise ValueError(f"no ports parsed from {spec!r}")
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
    return sorted(ports)


def probe_port(host: str, port: int, timeout: float = 1.0) -> PortResult:
    """Attempt a TCP connection to ``host:port`` and report whether it opened."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        is_open = sock.connect_ex((host, port)) == 0
    return PortResult(port=port, is_open=is_open)


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 100,
) -> list[PortResult]:
    """Concurrently probe ``ports`` on ``host``; results are sorted by port."""
    if not ports:
        return []
    worker_count = max(1, min(workers, len(ports)))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        results = pool.map(lambda p: probe_port(host, p, timeout), ports)
    return sorted(results, key=lambda r: r.port)


def sweep(network: str, port: int, timeout: float = 1.0, workers: int = 100) -> list[str]:
    """Return the hosts in ``network`` (CIDR) that accept a TCP connect on ``port``."""
    hosts = [str(ip) for ip in ipaddress.ip_network(network, strict=False).hosts()]
    if not hosts:
        return []
    worker_count = max(1, min(workers, len(hosts)))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        outcomes = pool.map(lambda h: (h, probe_port(h, port, timeout).is_open), hosts)
    return [host for host, is_open in outcomes if is_open]
