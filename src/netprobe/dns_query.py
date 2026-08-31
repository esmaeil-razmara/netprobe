"""A minimal DNS-over-UDP client built on the standard library.

Enough to ask a resolver for the common record types and parse the answer,
including compressed names. Not a general-purpose resolver -- no EDNS, no
retries, no TCP fallback for truncated responses.
"""

from __future__ import annotations

import secrets
import socket
import struct
from dataclasses import dataclass
from typing import Dict, List, Tuple

# name -> numeric type, for the types we can render
RECORD_TYPES: Dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
_TYPE_NAMES = {value: key for key, value in RECORD_TYPES.items()}


class DNSError(Exception):
    """Raised for malformed responses or resolver-reported failures."""


@dataclass(frozen=True)
class Record:
    name: str
    rtype: str
    ttl: int
    value: str


def _encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("idna") if label else b""
        if len(encoded) > 63:
            raise DNSError(f"label too long: {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    next_offset = offset
    steps = 0
    while True:
        if offset >= len(data):
            raise DNSError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DNSError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            steps += 1
            if steps > 128:
                raise DNSError("compression loop")
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("latin-1"))
        offset += length
    return (".".join(labels), next_offset)


def _parse_rdata(rtype: int, data: bytes, rdstart: int, rdlen: int) -> str:
    chunk = data[rdstart : rdstart + rdlen]
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntop(socket.AF_INET, chunk)
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, chunk)
    if rtype in (2, 5, 12):  # NS, CNAME, PTR
        return _read_name(data, rdstart)[0]
    if rtype == 15:  # MX
        (preference,) = struct.unpack_from("!H", data, rdstart)
        exchange = _read_name(data, rdstart + 2)[0]
        return f"{preference} {exchange}"
    if rtype == 16:  # TXT
        parts: List[str] = []
        i = rdstart
        end = rdstart + rdlen
        while i < end:
            slen = data[i]
            parts.append(data[i + 1 : i + 1 + slen].decode("latin-1"))
            i += 1 + slen
        return "".join(parts)
    if rtype == 6:  # SOA
        mname, off = _read_name(data, rdstart)
        rname, off = _read_name(data, off)
        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", data, off)
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    return chunk.hex()


def query(name: str, rtype: str, server: str = "1.1.1.1", timeout: float = 3.0) -> List[Record]:
    """Ask ``server`` for ``rtype`` records of ``name``."""
    type_num = RECORD_TYPES.get(rtype.upper())
    if type_num is None:
        raise DNSError(f"unsupported record type: {rtype}")

    query_id = secrets.randbelow(65536)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(name) + struct.pack("!HH", type_num, 1)
    packet = header + question

    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        try:
            response, _ = sock.recvfrom(4096)
        except socket.timeout:
            raise DNSError(f"no response from {server}")

    if len(response) < 12:
        raise DNSError("short response")
    resp_id, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", response, 0)
    if resp_id != query_id:
        raise DNSError("response id mismatch")
    rcode = flags & 0x0F
    if rcode == 3:
        raise DNSError("NXDOMAIN (name does not exist)")
    if rcode != 0:
        raise DNSError(f"resolver returned rcode {rcode}")

    offset = 12
    for _ in range(qd):
        _, offset = _read_name(response, offset)
        offset += 4  # qtype + qclass

    records: List[Record] = []
    for _ in range(an):
        rname, offset = _read_name(response, offset)
        rec_type, _cls, ttl, rdlen = struct.unpack_from("!HHIH", response, offset)
        offset += 10
        value = _parse_rdata(rec_type, response, offset, rdlen)
        offset += rdlen
        records.append(
            Record(
                name=rname,
                rtype=_TYPE_NAMES.get(rec_type, str(rec_type)),
                ttl=ttl,
                value=value,
            )
        )
    return records
