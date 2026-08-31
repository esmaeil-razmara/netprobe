import pytest

from netprobe import cisco_ssh
from netprobe.cisco_ssh import CiscoSSHError, is_read_only, run_commands
from netprobe.tools import get_tool


@pytest.mark.parametrize(
    "command, ok",
    [
        ("show version", True),
        ("show ip int brief", True),
        ("display interface", True),
        ("dir", True),
        ("ping 8.8.8.8", True),
        ("configure terminal", False),
        ("conf t", False),
        ("reload", False),
        ("write memory", False),
        ("no shutdown", False),
    ],
)
def test_is_read_only(command, ok):
    assert is_read_only(command) is ok


class _FakeConn:
    def __init__(self, responses):
        self.responses = responses
        self.enabled = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def enable(self):
        self.enabled = True

    def send_command(self, command, use_textfsm=False, read_timeout=30):
        value = self.responses[command]
        return value


def _patch_conn(monkeypatch, responses):
    monkeypatch.setattr(
        cisco_ssh, "ConnectHandler", lambda **kw: _FakeConn(responses)
    )


def test_run_commands_returns_output(monkeypatch):
    _patch_conn(monkeypatch, {"show version": "Cisco IOS XE, Version 17.9"})
    out = run_commands("10.0.0.1", "admin", "pw", ["show version"])
    assert out["show version"].startswith("Cisco IOS XE")


def test_run_commands_blocks_config(monkeypatch):
    _patch_conn(monkeypatch, {})
    with pytest.raises(CiscoSSHError, match="read-only"):
        run_commands("10.0.0.1", "admin", "pw", ["configure terminal"])


def test_run_commands_rejects_unknown_device_type(monkeypatch):
    _patch_conn(monkeypatch, {})
    with pytest.raises(CiscoSSHError, match="device_type"):
        run_commands("10.0.0.1", "a", "b", ["show run"], device_type="juniper_junos")


def test_run_commands_maps_auth_error(monkeypatch):
    from netmiko.exceptions import NetmikoAuthenticationException

    def boom(**kw):
        raise NetmikoAuthenticationException("bad creds")

    monkeypatch.setattr(cisco_ssh, "ConnectHandler", boom)
    with pytest.raises(CiscoSSHError, match="authentication"):
        run_commands("10.0.0.1", "admin", "wrong", ["show version"])


# -- tools --------------------------------------------------------------

def test_cisco_command_tool_raw_output(monkeypatch):
    import netprobe.tools.cisco_command_tool as mod

    monkeypatch.setattr(mod, "run_commands", lambda *a, **k: {"show clock": "12:00:00 UTC"})
    result = get_tool("cisco-command").run(
        {"host": "10.0.0.1", "username": "admin", "password": "pw", "command": "show clock"}
    )
    assert result.rows == [["12:00:00 UTC"]]


def test_cisco_command_tool_blocks_config():
    with pytest.raises(ValueError, match="read-only"):
        get_tool("cisco-command").run(
            {"host": "10.0.0.1", "username": "a", "password": "b", "command": "reload"}
        )


def test_cisco_mac_table_tool_parses_textfsm(monkeypatch):
    import netprobe.tools.cisco_mac_table_tool as mod

    records = [
        {"vlan": "10", "destination_address": "aabb.cc00.1122", "type": "DYNAMIC",
         "destination_port": "Gi1/0/1"},
        {"vlan": "20", "destination_address": "aabb.cc00.3344", "type": "DYNAMIC",
         "destination_port": ["Gi1/0/2"]},
    ]
    monkeypatch.setattr(mod, "run_commands", lambda *a, **k: {mod._CMD: records})
    result = get_tool("cisco-mac-table").run(
        {"host": "10.0.0.1", "username": "admin", "password": "pw"}
    )
    assert result.rows[0] == ["10", "aabb.cc00.1122", "DYNAMIC", "Gi1/0/1"]
    assert result.rows[1][3] == "Gi1/0/2"


def test_cisco_neighbors_tool_uses_saved_username(monkeypatch, isolated_inventory):
    from netprobe.inventory import Device
    import netprobe.tools.cisco_neighbors_tool as mod

    isolated_inventory.upsert(Device(host="10.0.0.1", username="netadmin", kind="cisco"))
    seen = {}

    def fake_run(host, username, password, commands, **kw):
        seen["username"] = username
        return {commands[0]: [{"local_interface": "Gi0/1", "neighbor_name": "core",
                               "neighbor_interface": "Gi0/24", "platform": "C9300",
                               "management_ip": "10.0.0.2"}]}

    monkeypatch.setattr(mod, "run_commands", fake_run)
    result = get_tool("cisco-neighbors").run(
        {"host": "10.0.0.1", "password": "pw"}  # no username in the form
    )
    assert seen["username"] == "netadmin"
    assert result.rows == [["Gi0/1", "core", "Gi0/24", "C9300", "10.0.0.2"]]


def test_cisco_tool_needs_password():
    with pytest.raises(ValueError, match="password"):
        get_tool("cisco-command").run(
            {"host": "10.0.0.1", "username": "admin", "command": "show version"}
        )
