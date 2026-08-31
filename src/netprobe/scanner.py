"""Core scanning helpers: parse port specs, TCP connect scan, subnet sweep."""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Optional


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


def tcp_latency(
    host: str,
    port: int,
    count: int = 4,
    timeout: float = 1.0,
) -> List[Optional[float]]:
    """Time ``count`` TCP handshakes to ``host:port``.

    Returns one entry per attempt: round-trip milliseconds on success, or
    ``None`` when the connection did not complete within ``timeout``.
    """
    samples: List[Optional[float]] = []
    for _ in range(max(1, count)):
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            connected = sock.connect_ex((host, port)) == 0
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        samples.append(round(elapsed_ms, 2) if connected else None)
    return samples


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


def monitor_endpoint(
    host: str,
    port: int,
    duration: float,
    interval: float,
    timeout: float = 2.0,
) -> List[tuple]:
    """Probe ``host:port`` every ``interval`` seconds for up to ``duration``.

    Returns ``(elapsed_seconds, latency_ms_or_None)`` tuples, one per sample.
    Always takes at least one sample.
    """
    interval = max(0.1, interval)
    started = time.perf_counter()
    samples: List[tuple] = []
    while True:
        elapsed = time.perf_counter() - started
        (latency,) = tcp_latency(host, port, count=1, timeout=timeout)
        samples.append((round(elapsed, 2), latency))
        if time.perf_counter() - started >= duration:
            break
        time.sleep(interval)
    return samples


def sweep(network: str, port: int, timeout: float = 1.0, workers: int = 100) -> list[str]:
    """Return the hosts in ``network`` (CIDR) that accept a TCP connect on ``port``."""
    hosts = [str(ip) for ip in ipaddress.ip_network(network, strict=False).hosts()]
    if not hosts:
        return []
    worker_count = max(1, min(workers, len(hosts)))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        outcomes = pool.map(lambda h: (h, probe_port(h, port, timeout).is_open), hosts)
    return [host for host, is_open in outcomes if is_open]
