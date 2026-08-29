import json
import socket
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from netprobe.tools import get_tool, load_tools
from netprobe.web.server import PanelHandler


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
def panel():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), PanelHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=1)


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, resp.read()


def _post(url, payload):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read())


def test_builtin_tools_are_registered():
    names = {tool.name for tool in load_tools()}
    assert {"scan", "sweep"} <= names


def test_scan_tool_reports_open_port(listening_port):
    result = get_tool("scan").run({"host": "127.0.0.1", "ports": str(listening_port)})
    assert result.rows == [[listening_port, "open"]]
    assert "1/1" in result.summary


def test_scan_tool_rejects_missing_host():
    with pytest.raises(ValueError):
        get_tool("scan").run({"ports": "80"})


def test_index_page_served(panel):
    status, body = _get(f"{panel}/")
    assert status == 200
    assert b"netprobe" in body


def test_api_lists_tools(panel):
    status, body = _get(f"{panel}/api/tools")
    assert status == 200
    tools = json.loads(body)["tools"]
    assert {t["name"] for t in tools} == {"scan", "sweep"}
    scan = next(t for t in tools if t["name"] == "scan")
    assert [f["name"] for f in scan["fields"]] == ["host", "ports", "timeout"]


def test_api_runs_scan(panel, listening_port):
    status, data = _post(
        f"{panel}/api/tools/scan",
        {"host": "127.0.0.1", "ports": str(listening_port)},
    )
    assert status == 200
    assert data["rows"] == [[listening_port, "open"]]


def test_api_bad_params_returns_400(panel):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{panel}/api/tools/scan", {"ports": "80"})
    assert exc.value.code == 400


def test_api_unknown_tool_returns_404(panel):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"{panel}/api/tools/nope", {})
    assert exc.value.code == 404
