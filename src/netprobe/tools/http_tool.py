"""Panel module: HTTP(S) endpoint check -- status, timing, redirects, headers."""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from typing import Dict

from . import Field, Result, Tool, register

_INTERESTING = (
    "server",
    "content-type",
    "content-length",
    "location",
    "cache-control",
    "strict-transport-security",
)


def _run(params: Dict[str, str]) -> Result:
    url = (params.get("url") or "").strip()
    if not url:
        raise ValueError("url is required")
    if "://" not in url:
        url = "https://" + url
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must be http:// or https://")
    method = (params.get("method") or "GET").strip().upper()
    timeout = float(params.get("timeout") or 5.0)

    request = urllib.request.Request(url, method=method)
    request.add_header("User-Agent", "netprobe/1")
    context = ssl.create_default_context()

    start = time.perf_counter()
    try:
        response = urllib.request.urlopen(request, timeout=timeout, context=context)
    except urllib.error.HTTPError as exc:
        response = exc  # still has status + headers
    except urllib.error.URLError as exc:
        raise ValueError(f"request failed: {exc.reason}")
    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 1)

    status = response.status
    rows = [
        ["status", f"{status} {response.reason}"],
        ["final url", response.url],
        ["elapsed", f"{elapsed_ms} ms"],
    ]
    for name in _INTERESTING:
        value = response.headers.get(name)
        if value:
            rows.append([name, value])

    try:
        response.close()
    except Exception:
        pass

    level = "ok" if status < 400 else "warn" if status < 500 else "error"
    return Result(
        columns=["field", "value"],
        rows=rows,
        summary=f"{method} {url} -> {status} in {elapsed_ms} ms",
        level=level,
    )


register(
    Tool(
        name="http",
        title="HTTP check",
        description="Fetch a URL and report status, timing and key response headers.",
        run=_run,
        fields=[
            Field("url", "URL", "text", "", "https://example.com"),
            Field("method", "Method", "text", "GET", required=False),
            Field("timeout", "Timeout (s)", "number", 5.0, required=False),
        ],
    )
)
