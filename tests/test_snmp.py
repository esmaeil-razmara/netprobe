import pytest

from netprobe import snmp
from netprobe.snmp import (
    SNMPError,
    _dec_oid,
    _enc_int,
    _enc_oid,
    _read_tlv,
    _tlv,
)
from netprobe.tools import get_tool


@pytest.mark.parametrize(
    "oid",
    [
        "1.3.6.1.2.1.2.2.1.2",
        "1.3.6.1.2.1.31.1.1.1.6.1000000",
        "0.0",
        "2.5.4.3",
    ],
)
def test_oid_encode_decode_roundtrip(oid):
    tag, body, _ = _read_tlv(_enc_oid(oid), 0)
    assert tag == 0x06
    assert _dec_oid(body) == oid


def test_enc_int_values():
    for value in (0, 1, 127, 128, 255, 300, 2_147_483_647):
        tag, body, _ = _read_tlv(_enc_int(value), 0)
        assert tag == 0x02
        assert int.from_bytes(body, "big", signed=True) == value


def _octet(s: bytes) -> bytes:
    return _tlv(0x04, s)


def _int(v: int) -> bytes:
    return _enc_int(v)


def _build_response(request_id, varbinds):
    """varbinds: list of (oid_str, value_bytes_tlv)."""
    vbs = b"".join(_tlv(0x30, _enc_oid(o) + v) for o, v in varbinds)
    pdu = _int(request_id) + _int(0) + _int(0) + _tlv(0x30, vbs)
    message = _tlv(0x30, _int(1) + _octet(b"public") + _tlv(0xA2, pdu))
    return message


class _FakeSock:
    """Replays a canned response, echoing the request id it was sent."""

    sent = None

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, _):
        pass

    def sendto(self, packet, _addr):
        type(self).sent = packet

    def recvfrom(self, _n):
        message = self.sent
        _t, body, _ = _read_tlv(message, 0)
        _t, _ver, off = _read_tlv(body, 0)
        _t, _comm, off = _read_tlv(body, off)
        _t, pdu, _ = _read_tlv(body, off)
        _t, rid_b, _ = _read_tlv(pdu, 0)
        request_id = int.from_bytes(rid_b, "big")
        varbinds = [
            ("1.3.6.1.2.1.1.5.0", _octet(b"switch-01")),
            ("1.3.6.1.2.1.1.3.0", _tlv(0x43, (12345).to_bytes(4, "big"))),
        ]
        return _build_response(request_id, varbinds), ("10.0.0.1", 161)


def test_get_parses_varbinds(monkeypatch):
    monkeypatch.setattr(snmp.socket, "socket", lambda *a, **k: _FakeSock())
    result = snmp.get("10.0.0.1", "public", ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"])
    assert result["1.3.6.1.2.1.1.5.0"] == "switch-01"
    assert result["1.3.6.1.2.1.1.3.0"] == 12345


def test_get_times_out(monkeypatch):
    import socket as _socket

    class _Timeout(_FakeSock):
        def recvfrom(self, _n):
            raise _socket.timeout()

    monkeypatch.setattr(snmp.socket, "socket", lambda *a, **k: _Timeout())
    with pytest.raises(SNMPError):
        snmp.get("10.0.0.1", "public", ["1.3.6.1.2.1.1.5.0"], timeout=0.1, retries=2)


def test_response_id_mismatch(monkeypatch):
    class _WrongId(_FakeSock):
        def recvfrom(self, _n):
            return _build_response(999999, [("1.3.6.1.2.1.1.5.0", _octet(b"x"))]), ("10.0.0.1", 161)

    monkeypatch.setattr(snmp.socket, "socket", lambda *a, **k: _WrongId())
    with pytest.raises(SNMPError):
        snmp.get("10.0.0.1", "public", ["1.3.6.1.2.1.1.5.0"])


# -- device tools built on the SNMP client ---------------------------

_IF_DATA = {
    "1.3.6.1.2.1.2.2.1.2": [("1.3.6.1.2.1.2.2.1.2.1", "Gi0/1"),
                            ("1.3.6.1.2.1.2.2.1.2.2", "Gi0/2")],
    "1.3.6.1.2.1.2.2.1.7": [("1.3.6.1.2.1.2.2.1.7.1", 1),
                            ("1.3.6.1.2.1.2.2.1.7.2", 2)],
    "1.3.6.1.2.1.2.2.1.8": [("1.3.6.1.2.1.2.2.1.8.1", 1),
                            ("1.3.6.1.2.1.2.2.1.8.2", 2)],
    "1.3.6.1.2.1.31.1.1.1.15": [("1.3.6.1.2.1.31.1.1.1.15.1", 1000),
                                ("1.3.6.1.2.1.31.1.1.1.15.2", 1000)],
    "1.3.6.1.2.1.31.1.1.1.18": [],
}


def test_snmp_interfaces_tool(monkeypatch):
    import netprobe.tools.snmp_interfaces_tool as mod

    monkeypatch.setattr(mod, "walk", lambda h, c, base, **k: _IF_DATA.get(base, []))
    result = get_tool("snmp-interfaces").run({"host": "10.0.0.1", "community": "public"})
    assert result.summary.startswith("1/2 interface")
    assert result.rows[0] == ["1", "Gi0/1", "up", "up", "1000 Mbps"]


def test_snmp_bandwidth_tool(monkeypatch):
    import netprobe.tools.snmp_bandwidth_tool as mod

    counters = iter([
        # first sample: HC in/out
        [("1.3.6.1.2.1.31.1.1.1.6.1", 1_000_000)],
        [("1.3.6.1.2.1.31.1.1.1.10.1", 2_000_000)],
        # second sample
        [("1.3.6.1.2.1.31.1.1.1.6.1", 2_000_000)],
        [("1.3.6.1.2.1.31.1.1.1.10.1", 2_500_000)],
        # descr + speed lookups
        [("1.3.6.1.2.1.2.2.1.2.1", "Gi0/1")],
        [("1.3.6.1.2.1.31.1.1.1.15.1", 1000)],
    ])
    monkeypatch.setattr(mod, "walk", lambda h, c, base, **k: next(counters))
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    result = get_tool("snmp-bandwidth").run(
        {"host": "10.0.0.1", "community": "public", "interval": "10"}
    )
    assert result.rows and result.rows[0][0] == "Gi0/1"


def test_snmp_tool_uses_saved_community(monkeypatch, isolated_inventory):
    from netprobe.inventory import Device
    import netprobe.tools.snmp_interfaces_tool as mod

    isolated_inventory.upsert(Device(host="10.0.0.1", community="s3cret", kind="cisco"))
    seen = {}

    def fake_walk(host, community, base, **k):
        seen["community"] = community
        return _IF_DATA.get(base, [])

    monkeypatch.setattr(mod, "walk", fake_walk)
    get_tool("snmp-interfaces").run({"host": "10.0.0.1"})  # no community in the form
    assert seen["community"] == "s3cret"


def test_snmp_tool_errors_without_any_community(isolated_inventory):
    with pytest.raises(ValueError, match="community"):
        get_tool("snmp-interfaces").run({"host": "10.9.9.9"})


def test_snmp_discover_finds_and_saves(monkeypatch, isolated_inventory):
    import netprobe.tools.snmp_discover_tool as mod

    def fake_get(host, community, oids, **k):
        if host == "10.0.0.2":
            return {"1.3.6.1.2.1.1.5.0": "edge-sw", "1.3.6.1.2.1.1.1.0": "Cisco IOS Software"}
        raise mod.SNMPError("timeout")

    monkeypatch.setattr(mod, "get", fake_get)
    result = get_tool("snmp-discover").run(
        {"range": "10.0.0.1-4", "community": "public", "save": "1"}
    )
    assert result.rows == [["10.0.0.2", "edge-sw", "cisco", "Cisco IOS Software"]]
    assert "saved 1" in result.summary
    saved = isolated_inventory.get("10.0.0.2")
    assert saved and saved.community == "public" and saved.kind == "cisco"


def test_devices_tool_add_list_remove(isolated_inventory):
    add = get_tool("devices").run(
        {"action": "add", "host": "10.0.0.5", "name": "sw5", "kind": "cisco"}
    )
    assert any(row[0] == "10.0.0.5" for row in add.rows)
    listed = get_tool("devices").run({"action": "list"})
    assert listed.rows[0][0] == "10.0.0.5"
    removed = get_tool("devices").run({"action": "remove", "host": "10.0.0.5"})
    assert removed.rows == []
