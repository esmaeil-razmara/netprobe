import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from netprobe.scanner import tcp_latency
from netprobe.tools import get_tool
from netprobe.tools.tls_tool import summarise_cert


@pytest.fixture
def listening_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                server.accept()[0].close()
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


@pytest.fixture
def http_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Test", "1")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    try:
        yield f"http://{host}:{port}/"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=1)


# -- scanner.tcp_latency ------------------------------------------------

def test_tcp_latency_measures_open_port(listening_port):
    samples = tcp_latency("127.0.0.1", listening_port, count=3, timeout=1.0)
    assert len(samples) == 3
    assert all(isinstance(s, float) for s in samples)


def test_tcp_latency_reports_none_on_closed_port():
    assert tcp_latency("127.0.0.1", 1, count=2, timeout=0.3) == [None, None]


# -- dns --------------------------------------------------------------

def test_dns_forward_lookup_localhost():
    result = get_tool("dns").run({"target": "localhost"})
    addrs = {value for _type, value in result.rows}
    assert "127.0.0.1" in addrs or "::1" in addrs


def test_dns_rejects_unresolvable():
    with pytest.raises(ValueError):
        get_tool("dns").run({"target": "no-such-host.invalid"})


def test_dns_requires_target():
    with pytest.raises(ValueError):
        get_tool("dns").run({})


# -- http -----------------------------------------------------------

def test_http_check_reports_status(http_server):
    result = get_tool("http").run({"url": http_server})
    fields = dict(result.rows)
    assert fields["status"].startswith("200")
    assert result.level == "ok"


def test_http_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        get_tool("http").run({"url": "ftp://example.com"})


# -- tls ----------------------------------------------------------

def test_summarise_cert_extracts_fields_and_expiry():
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notBefore": "Jan  1 00:00:00 2020 GMT",
        "notAfter": "Jan  1 00:00:00 2035 GMT",
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }
    rows = dict(summarise_cert(cert))
    assert rows["subject"] == "commonName=example.com"
    assert rows["SAN"] == "example.com, www.example.com"
    assert int(rows["days remaining"]) > 3000


def test_tls_connection_failure_raises_valueerror():
    with pytest.raises(ValueError):
        get_tool("tls").run({"host": "127.0.0.1", "port": 1, "timeout": 0.3})


# -- tcping -------------------------------------------------------

def test_tcping_reports_latency(listening_port):
    result = get_tool("tcping").run(
        {"host": "127.0.0.1", "port": str(listening_port), "count": "3"}
    )
    assert len(result.rows) == 3
    assert "3/3 ok" in result.summary


def test_tcping_rejects_bad_count():
    with pytest.raises(ValueError):
        get_tool("tcping").run({"host": "127.0.0.1", "count": "999"})
