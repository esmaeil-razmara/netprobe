import os

import pytest

_RUN_NETWORK = os.environ.get("NETPROBE_NETWORK_TESTS") == "1"


def pytest_collection_modifyitems(config, items):
    """Skip tests marked ``network`` unless NETPROBE_NETWORK_TESTS=1.

    These tests reach out to the public internet (DNS resolvers, WHOIS, TLS
    hosts) and are not run in CI by default.
    """
    if _RUN_NETWORK:
        return
    skip = pytest.mark.skip(reason="set NETPROBE_NETWORK_TESTS=1 to run network tests")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip)
