import socket
import threading

import pytest

from netprobe.scanner import parse_ports, probe_port, scan_ports


@pytest.fixture
def listening_port():
    """Bind a throwaway TCP server on localhost and yield its port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    stop = threading.Event()

    def serve():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except socket.timeout:
                continue

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        thread.join(timeout=1)
        server.close()


def test_parse_ports_single_and_range():
    assert parse_ports("22, 80, 8000-8002") == [22, 80, 8000, 8001, 8002]


def test_parse_ports_dedupes_and_sorts():
    assert parse_ports("80,80,79") == [79, 80]


@pytest.mark.parametrize("spec", ["", "0", "70000", "10-5", "abc"])
def test_parse_ports_rejects_bad_input(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


def test_probe_port_detects_open(listening_port):
    assert probe_port("127.0.0.1", listening_port, timeout=1.0).is_open is True


def test_probe_port_detects_closed():
    # Port 1 is almost never listening in a test environment.
    assert probe_port("127.0.0.1", 1, timeout=0.5).is_open is False


def test_scan_ports_finds_the_listener(listening_port):
    results = scan_ports("127.0.0.1", [1, listening_port], timeout=1.0)
    open_ports = {r.port for r in results if r.is_open}
    assert listening_port in open_ports
    assert results == sorted(results, key=lambda r: r.port)


def test_scan_ports_empty_list():
    assert scan_ports("127.0.0.1", []) == []
