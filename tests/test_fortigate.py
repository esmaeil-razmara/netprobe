import json
import urllib.error

import pytest

from netprobe import fortigate
from netprobe.fortigate import FortiGate, FortiGateError
from netprobe.tools import get_tool


class _FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def _patch_urlopen(monkeypatch, handler):
    def fake_urlopen(request, timeout=None, context=None):
        return handler(request.full_url, dict(request.header_items()))

    monkeypatch.setattr(fortigate.urllib.request, "urlopen", fake_urlopen)


def test_client_sends_bearer_token(monkeypatch):
    seen = {}

    def handler(url, headers):
        seen["url"] = url
        seen["headers"] = headers
        return _FakeResponse({"results": {"port1": {"link": True}}})

    _patch_urlopen(monkeypatch, handler)
    fg = FortiGate("10.0.0.254", "secret-token", verify=False)
    data = fg.get("/api/v2/monitor/system/interface", {"include_vlan": "true"})

    assert data["results"]["port1"]["link"] is True
    assert "10.0.0.254" in seen["url"]
    assert seen["headers"].get("Authorization") == "Bearer secret-token"


def test_client_maps_401_to_auth_error(monkeypatch):
    def handler(url, headers):
        raise urllib.error.HTTPError(url, 401, "Unauthorized", {}, None)

    _patch_urlopen(monkeypatch, handler)
    with pytest.raises(FortiGateError, match="authentication"):
        FortiGate("h", "bad").get("/api/v2/monitor/system/status")


def test_fortigate_interfaces_tool(monkeypatch):
    payload = {
        "results": {
            "wan1": {"link": True, "speed": 1000, "ip": "203.0.113.2",
                     "rx_bytes": 5_000_000, "tx_bytes": 1_000_000,
                     "rx_errors": 0, "tx_errors": 2, "type": "physical"},
            "wan2": {"link": False, "speed": 0, "ip": "0.0.0.0",
                     "rx_bytes": 0, "tx_bytes": 0, "type": "physical"},
        }
    }
    _patch_urlopen(monkeypatch, lambda u, h: _FakeResponse(payload))
    result = get_tool("fortigate-interfaces").run(
        {"host": "10.0.0.254", "token": "t", "verify": "0"}
    )
    assert result.summary.startswith("1/2 interface")
    names = {row[0] for row in result.rows}
    assert names == {"wan1", "wan2"}


def test_fortigate_top_talkers_aggregates(monkeypatch):
    payload = {
        "results": [
            {"source": "10.0.0.5", "bytes": 1000},
            {"source": "10.0.0.5", "bytes": 500},
            {"source": "10.0.0.9", "bytes": 4000},
        ]
    }
    _patch_urlopen(monkeypatch, lambda u, h: _FakeResponse(payload))
    result = get_tool("fortigate-top-talkers").run(
        {"host": "10.0.0.254", "token": "t"}
    )
    assert result.rows[0][0] == "10.0.0.9"  # heaviest first
    assert result.rows[1][0] == "10.0.0.5"
    assert result.rows[1][2] == 2  # two sessions aggregated


def test_fortigate_wan_tool(monkeypatch):
    payload = {
        "results": {
            "sla-isp": {
                "wan1": {"status": "up", "latency": 12.5, "jitter": 1.2, "packet_loss": 0.0},
                "wan2": {"status": "down", "latency": 0, "jitter": 0, "packet_loss": 100.0},
            }
        }
    }
    _patch_urlopen(monkeypatch, lambda u, h: _FakeResponse(payload))
    result = get_tool("fortigate-wan").run({"host": "10.0.0.254", "token": "t"})
    assert result.summary.startswith("1/2 WAN member")
    assert result.level == "warn"


def test_fortigate_tool_requires_credentials():
    with pytest.raises(ValueError):
        get_tool("fortigate-wan").run({"host": "10.0.0.254"})
