"""Thin FortiGate FortiOS REST API client (standard library only)."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional


class FortiGateError(Exception):
    pass


class FortiGate:
    """Talk to the FortiOS monitor/config REST API with a bearer token.

    ``verify=False`` accepts the appliance's self-signed certificate, which is
    the common case on a management interface -- only do this on a trusted
    network path.
    """

    def __init__(self, host: str, token: str, port: int = 443,
                 verify: bool = True, timeout: float = 10.0) -> None:
        self.base = f"https://{host}:{port}"
        self.token = token
        self.timeout = timeout
        if verify:
            self._ctx: Optional[ssl.SSLContext] = ssl.create_default_context()
        else:
            self._ctx = ssl._create_unverified_context()

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        request = urllib.request.Request(url, method="GET")
        request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout,
                                        context=self._ctx) as response:
                payload = json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise FortiGateError("authentication failed (check the API token)")
            raise FortiGateError(f"HTTP {exc.code} from {path}")
        except urllib.error.URLError as exc:
            raise FortiGateError(f"cannot reach {self.base}: {exc.reason}")
        except ssl.SSLError as exc:
            raise FortiGateError(f"TLS error ({exc}); try disabling verification")
        return payload
