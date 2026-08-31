"""A tiny stdlib HTTP server that exposes the tool registry as a JSON API
plus a static single-page panel.

Routes:
    GET  /                     -> the panel
    GET  /static/<path>        -> panel assets
    GET  /api/tools            -> [{name, title, description, fields[]}]
    POST /api/tools/<name>     -> run the tool with a JSON object body
"""

from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ..inventory import Device, get_inventory
from ..tools import get_tool, load_tools

STATIC_DIR = Path(__file__).parent / "static"


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "netprobe-panel/1"

    # -- helpers ---------------------------------------------------------
    def _json(self, obj: object, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _file(self, path: Path) -> None:
        static_root = STATIC_DIR.resolve()
        resolved = path.resolve()
        if static_root != resolved and static_root not in resolved.parents:
            self._json({"error": "forbidden"}, 403)
            return
        if not resolved.is_file():
            self._json({"error": "not found"}, 404)
            return
        ctype = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
        body = resolved.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # -- routing --------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - required name
        route = self.path.split("?", 1)[0]
        if route == "/":
            self._file(STATIC_DIR / "index.html")
        elif route == "/api/tools":
            self._json({"tools": [t.to_dict() for t in load_tools()]})
        elif route == "/api/inventory":
            self._json({"devices": [d.public() for d in get_inventory().list()]})
        elif route.startswith("/static/"):
            self._file(STATIC_DIR / route[len("/static/") :])
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802 - required name
        # Always drain the request body first: replying while bytes are still
        # unread makes some clients see a connection reset instead of the status.
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        route = self.path.split("?", 1)[0]

        try:
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError("request body must be a JSON object")
            if route == "/api/inventory":
                self._json(self._inventory_write(body))
                return
            prefix = "/api/tools/"
            if not route.startswith(prefix):
                self._json({"error": "not found"}, 404)
                return
            tool = get_tool(route[len(prefix):])
            if tool is None:
                self._json({"error": "unknown tool"}, 404)
                return
            self._json(tool.run(body).to_dict())
        except ValueError as exc:
            self._json({"error": str(exc)}, 400)
        except Exception as exc:  # report, don't take the panel down
            self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    @staticmethod
    def _inventory_write(body: dict) -> dict:
        inv = get_inventory()
        if body.get("action") == "remove":
            removed = inv.remove(str(body.get("host", "")))
            return {"removed": removed, "devices": [d.public() for d in inv.list()]}
        entries = body.get("devices")
        if entries is None:
            entries = [body]
        for entry in entries:
            inv.upsert(Device(
                host=str(entry.get("host", "")).strip(),
                name=str(entry.get("name", "")).strip(),
                kind=str(entry.get("kind", "other")).strip() or "other",
                community=str(entry.get("community", "")),
                notes=str(entry.get("notes", "")).strip(),
            ))
        return {"devices": [d.public() for d in inv.list()]}

    def log_message(self, *_args) -> None:  # keep the console quiet
        pass


def serve(host: str = "127.0.0.1", port: int = 8765,
          data_dir: "str | None" = None) -> None:
    if data_dir is not None:
        from ..inventory import set_data_dir

        set_data_dir(data_dir)
    load_tools()
    inv = get_inventory()
    httpd = ThreadingHTTPServer((host, port), PanelHandler)
    bound_host, bound_port = httpd.server_address[:2]
    print(f"netprobe panel: http://{bound_host}:{bound_port}  (Ctrl+C to stop)")
    print(f"device inventory: {inv.path}  (may hold SNMP community strings)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        httpd.server_close()
