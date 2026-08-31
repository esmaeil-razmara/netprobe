"""A minimal SNMPv2c client (GET and GETBULK walk) built on the standard library.

No authentication or privacy -- community string only, like ``snmpget -v2c``.
Enough to read the interface tables off a switch or router.
"""

from __future__ import annotations

import secrets
import socket
import struct
from typing import Dict, List, Tuple

# BER / SNMP tags
_INTEGER = 0x02
_OCTET_STRING = 0x04
_NULL = 0x05
_OID = 0x06
_SEQUENCE = 0x30
_GET_REQUEST = 0xA0
_GETBULK_REQUEST = 0xA5
_GET_RESPONSE = 0xA2
_IPADDRESS = 0x40
_COUNTER32 = 0x41
_GAUGE32 = 0x42
_TIMETICKS = 0x43
_COUNTER64 = 0x46
_NO_SUCH_OBJECT = 0x80
_NO_SUCH_INSTANCE = 0x81
_END_OF_MIB_VIEW = 0x82

_EXCEPTION_TAGS = {_NO_SUCH_OBJECT, _NO_SUCH_INSTANCE, _END_OF_MIB_VIEW}


class SNMPError(Exception):
    """Raised on transport failure or an error-status in the response PDU."""


# --------------------------------------------------------------------- encoding


def _enc_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def _enc_int(value: int) -> bytes:
    if value == 0:
        return _tlv(_INTEGER, b"\x00")
    length = (value.bit_length() + 8) // 8  # room for the sign bit
    return _tlv(_INTEGER, value.to_bytes(length, "big", signed=True))


def _enc_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise SNMPError(f"invalid OID: {oid!r}")
    body = bytearray([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        if arc < 0x80:
            body.append(arc)
            continue
        chunks = []
        while arc:
            chunks.append(arc & 0x7F)
            arc >>= 7
        chunks.reverse()
        for i in range(len(chunks) - 1):
            chunks[i] |= 0x80
        body.extend(chunks)
    return _tlv(_OID, bytes(body))


def _varbind(oid: str) -> bytes:
    return _tlv(_SEQUENCE, _enc_oid(oid) + _tlv(_NULL, b""))


# --------------------------------------------------------------------- decoding


def _read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    tag = data[offset]
    first = data[offset + 1]
    if first < 0x80:
        length = first
        start = offset + 2
    else:
        n = first & 0x7F
        length = int.from_bytes(data[offset + 2 : offset + 2 + n], "big")
        start = offset + 2 + n
    return tag, data[start : start + length], start + length


def _dec_oid(body: bytes) -> str:
    first = body[0]
    arcs = [first // 40, first % 40]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return ".".join(str(a) for a in arcs)


def _dec_value(tag: int, body: bytes):
    if tag in _EXCEPTION_TAGS:
        return {
            _NO_SUCH_OBJECT: "noSuchObject",
            _NO_SUCH_INSTANCE: "noSuchInstance",
            _END_OF_MIB_VIEW: "endOfMibView",
        }[tag]
    if tag == _INTEGER:
        return int.from_bytes(body, "big", signed=True)
    if tag in (_COUNTER32, _GAUGE32, _TIMETICKS, _COUNTER64):
        return int.from_bytes(body, "big")
    if tag == _IPADDRESS and len(body) == 4:
        return ".".join(str(b) for b in body)
    if tag == _OID:
        return _dec_oid(body)
    if tag == _NULL:
        return None
    # OCTET STRING and anything else: printable text if we can, else hex
    try:
        text = body.decode("utf-8")
        if all(ch == "\t" or ch == "\n" or 32 <= ord(ch) < 127 for ch in text):
            return text
    except UnicodeDecodeError:
        pass
    return body.hex()


def _parse_response(packet: bytes, want_id: int) -> List[Tuple[str, object]]:
    _tag, message, _ = _read_tlv(packet, 0)
    _t, _version, off = _read_tlv(message, 0)
    _t, _community, off = _read_tlv(message, off)
    pdu_tag, pdu, _ = _read_tlv(message, off)
    if pdu_tag != _GET_RESPONSE:
        raise SNMPError(f"unexpected PDU tag 0x{pdu_tag:02x}")

    _t, rid_b, p = _read_tlv(pdu, 0)
    _t, err_status_b, p = _read_tlv(pdu, p)
    _t, err_index_b, p = _read_tlv(pdu, p)
    if int.from_bytes(rid_b, "big") != want_id:
        raise SNMPError("response id mismatch")
    err_status = int.from_bytes(err_status_b, "big")
    if err_status:
        raise SNMPError(f"agent error-status {err_status} at index "
                        f"{int.from_bytes(err_index_b, 'big')}")

    _t, vb_list, _ = _read_tlv(pdu, p)
    results: List[Tuple[str, object]] = []
    i = 0
    while i < len(vb_list):
        _t, vb, i = _read_tlv(vb_list, i)
        _t, oid_b, j = _read_tlv(vb, 0)
        val_tag, val_b, _ = _read_tlv(vb, j)
        results.append((_dec_oid(oid_b), _dec_value(val_tag, val_b)))
    return results


# --------------------------------------------------------------------- public


def _exchange(host: str, community: str, pdu_tag: int, pdu_fields: bytes,
              oids: List[str], timeout: float, retries: int) -> List[Tuple[str, object]]:
    request_id = secrets.randbelow(0x7FFFFFFF) + 1
    pdu_body = (
        _enc_int(request_id)
        + pdu_fields
        + _tlv(_SEQUENCE, b"".join(_varbind(o) for o in oids))
    )
    message = _tlv(
        _SEQUENCE,
        _enc_int(1)  # version 2c
        + _tlv(_OCTET_STRING, community.encode())
        + _tlv(pdu_tag, pdu_body),
    )

    last_error = "no response"
    for _ in range(max(1, retries)):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(message, (host, 161))
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                last_error = f"no response from {host}:161"
                continue
        return _parse_response(data, request_id)
    raise SNMPError(last_error)


def get(host: str, community: str, oids: List[str], timeout: float = 2.0,
        retries: int = 2) -> Dict[str, object]:
    """SNMP GET for one or more fully-qualified OIDs."""
    pairs = _exchange(host, community, _GET_REQUEST,
                      _enc_int(0) + _enc_int(0), oids, timeout, retries)
    return {oid: value for oid, value in pairs}


def walk(host: str, community: str, base_oid: str, timeout: float = 2.0,
         retries: int = 2, max_rows: int = 2000) -> List[Tuple[str, object]]:
    """Walk the subtree under ``base_oid`` using repeated GETBULK requests."""
    base = base_oid.strip(".")
    prefix = base + "."
    results: List[Tuple[str, object]] = []
    current = base
    while len(results) < max_rows:
        # non-repeaters=0, max-repetitions=25
        pairs = _exchange(host, community, _GETBULK_REQUEST,
                          _enc_int(0) + _enc_int(25), [current], timeout, retries)
        if not pairs:
            break
        advanced = False
        for oid, value in pairs:
            if oid != prefix[:-1] and not oid.startswith(prefix):
                return results
            if value == "endOfMibView":
                return results
            results.append((oid, value))
            current = oid
            advanced = True
        if not advanced:
            break
    return results
