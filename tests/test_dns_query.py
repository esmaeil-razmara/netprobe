import struct

import pytest

from netprobe import dns_query
from netprobe.dns_query import DNSError, _encode_qname, _parse_rdata, _read_name


def test_encode_qname_roundtrips_labels():
    assert _encode_qname("example.com") == b"\x07example\x03com\x00"
    assert _encode_qname("a.") == b"\x01a\x00"


def test_read_name_plain():
    data = b"\x03www\x07example\x03com\x00rest"
    name, offset = _read_name(data, 0)
    assert name == "www.example.com"
    assert data[offset:] == b"rest"


def test_read_name_follows_compression_pointer():
    # bytes 0..12: "example.com\0" ; then a name that is just a pointer to 0
    base = b"\x07example\x03com\x00"
    data = base + b"\xc0\x00"
    name, offset = _read_name(data, len(base))
    assert name == "example.com"
    assert offset == len(data)  # consumed the 2 pointer bytes only


def test_read_name_rejects_compression_loop():
    data = b"\xc0\x02\xc0\x00"  # points at itself
    with pytest.raises(DNSError):
        _read_name(data, 0)


def test_parse_rdata_a_and_txt():
    a = _parse_rdata(1, b"\x5d\xb8\xd8\x22", 0, 4)
    assert a == "93.184.216.34"
    packet = b"\x0bhello world"
    assert _parse_rdata(16, packet, 0, len(packet)) == "hello world"


def test_parse_rdata_mx_uses_preference_and_name():
    # preference 10, then "mail.example.com"
    rdata = struct.pack("!H", 10) + b"\x04mail\x07example\x03com\x00"
    assert _parse_rdata(15, rdata, 0, len(rdata)) == "10 mail.example.com"


def _build_response(qname="example.com", ip="93.184.216.34"):
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = _encode_qname(qname) + struct.pack("!HH", 1, 1)
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 300, 4)
        + bytes(int(o) for o in ip.split("."))
    )
    return header + question + answer


def test_query_parses_a_record(monkeypatch):
    response = _build_response()

    class FakeSock:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, _):
            pass

        def sendto(self, *_):
            pass

        def recvfrom(self, _):
            return response, ("1.1.1.1", 53)

    # _build_response() hard-codes id 0x1234, so pin the generated id to match
    monkeypatch.setattr(dns_query.secrets, "randbelow", lambda _n: 0x1234)
    monkeypatch.setattr(dns_query.socket, "socket", lambda *a, **k: FakeSock())

    records = dns_query.query("example.com", "A", server="1.1.1.1")
    assert len(records) == 1
    assert records[0].rtype == "A"
    assert records[0].value == "93.184.216.34"
    assert records[0].ttl == 300


def test_query_rejects_unknown_type():
    with pytest.raises(DNSError):
        dns_query.query("example.com", "WKS")


@pytest.mark.network
def test_query_live_resolver():
    import ipaddress

    records = dns_query.query("one.one.one.one", "A", server="1.1.1.1")
    assert records, "resolver returned no A records"
    for rec in records:
        assert rec.rtype == "A"
        ipaddress.IPv4Address(rec.value)  # raises if not a valid v4 address
