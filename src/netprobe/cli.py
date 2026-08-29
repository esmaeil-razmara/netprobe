"""Command-line interface for netprobe."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .scanner import parse_ports, scan_ports, sweep


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description="Small TCP network probing toolkit.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="per-connection timeout in seconds (default: 1.0)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="TCP connect scan of one host")
    scan.add_argument("host")
    scan.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help="port spec, e.g. '22,80,8000-8010' (default: 1-1024)",
    )

    sweep_cmd = sub.add_parser("sweep", help="find hosts in a subnet with a port open")
    sweep_cmd.add_argument("network", help="CIDR, e.g. 192.168.1.0/24")
    sweep_cmd.add_argument("-p", "--port", type=int, default=80, help="port (default: 80)")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scan":
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        results = scan_ports(args.host, ports, timeout=args.timeout)
        open_ports = [r.port for r in results if r.is_open]
        for port in open_ports:
            print(f"{args.host}:{port} open")
        print(f"{len(open_ports)}/{len(results)} ports open", file=sys.stderr)
        return 0

    if args.command == "sweep":
        live = sweep(args.network, args.port, timeout=args.timeout)
        for host in live:
            print(f"{host}:{args.port} open")
        print(f"{len(live)} host(s) responding", file=sys.stderr)
        return 0

    return 1  # pragma: no cover - argparse enforces a valid command


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
