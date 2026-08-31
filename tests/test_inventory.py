import json

import pytest

from netprobe.inventory import Device, Inventory


@pytest.fixture
def inv(tmp_path):
    return Inventory(tmp_path / "devices.json")


def test_upsert_then_list(inv):
    inv.upsert(Device(host="10.0.0.1", name="sw1", kind="cisco", community="public"))
    devices = inv.list()
    assert len(devices) == 1
    assert devices[0].host == "10.0.0.1"
    assert devices[0].added  # date filled in


def test_upsert_updates_in_place_and_keeps_community(inv):
    inv.upsert(Device(host="10.0.0.1", name="sw1", community="public"))
    inv.upsert(Device(host="10.0.0.1", name="core-sw"))  # no community this time
    devices = inv.list()
    assert len(devices) == 1
    assert devices[0].name == "core-sw"
    assert devices[0].community == "public"  # preserved


def test_remove(inv):
    inv.upsert(Device(host="10.0.0.1"))
    assert inv.remove("10.0.0.1") is True
    assert inv.remove("10.0.0.1") is False
    assert inv.list() == []


def test_invalid_kind_becomes_other(inv):
    inv.upsert(Device(host="10.0.0.1", kind="bogus"))
    assert inv.get("10.0.0.1").kind == "other"


def test_upsert_requires_host(inv):
    with pytest.raises(ValueError):
        inv.upsert(Device(host=""))


def test_public_hides_community(inv):
    inv.upsert(Device(host="10.0.0.1", community="secret"))
    public = inv.get("10.0.0.1").public()
    assert "community" not in public
    assert public["has_community"] is True


def test_corrupt_file_is_treated_as_empty(tmp_path):
    path = tmp_path / "devices.json"
    path.write_text("{ not json")
    assert Inventory(path).list() == []


def test_file_is_valid_json(inv):
    inv.upsert(Device(host="10.0.0.1", name="x"))
    data = json.loads(inv.path.read_text())
    assert isinstance(data, list) and data[0]["host"] == "10.0.0.1"
