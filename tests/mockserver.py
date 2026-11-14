"""Local servers used only by the test suite.

Two endpoints model the two cases that matter for accuracy:

* ``/ping?host=`` is genuinely *vulnerable*: it emulates a shell, so ``echo`` and
  arithmetic (``$((a*b))``, ``expr a \\* b``, ``set /a``) actually evaluate. A
  real injection produces computed output — the confirmation step should pass.
* ``/search?q=`` merely *reflects* its input verbatim without executing anything
  (like a search box or error page). A marker shows up in the response, but no
  command runs — the confirmation step should REJECT it as a false positive.

Nothing here runs a real shell.
"""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_CANNED = {
    "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "whoami": "www-data",
    "uname -a": "Linux mock-web 6.1.0 #1 SMP x86_64 GNU/Linux",
    "pwd": "/var/www/html",
}


def _fake_shell(value: str) -> str:
    """Emulate just enough shell to execute our echo/arithmetic probes."""
    # Arithmetic executed in a shell context -> returns the product.
    am = re.search(r"(\d{2,})\s*\\?\*\s*(\d{2,})", value)
    if am and any(t in value for t in ("$((", "expr", "set /a", "$(", "`")):
        return str(int(am.group(1)) * int(am.group(2)))

    m = re.search(r"echo\s+(.+)", value)
    if not m:
        return ""
    arg = m.group(1).strip().strip(";").strip("`").strip()

    def _sub(match: re.Match) -> str:
        cmd = match.group(1).split("2>&1")[0].strip()
        return _CANNED.get(cmd, f"[[{cmd}]]")

    return re.sub(r"\$\(([^)]*)\)", _sub, arg)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, body: str):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self, path: str, params: dict):
        if path.startswith("/search"):
            # Reflection only: echo the input back, execute nothing.
            q = params.get("q", [""])[0]
            self._send(f"<html><body>No results for: {q}</body></html>")
        else:
            # Vulnerable: the host value reaches an emulated shell.
            host = params.get("host", [""])[0]
            self._send(f"<html><body>PING result: {_fake_shell(host)}\n</body></html>")

    def do_GET(self):
        parsed = urlparse(self.path)
        self._handle(parsed.path, parse_qs(parsed.query, keep_blank_values=True))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode() if length else ""
        self._handle(urlparse(self.path).path, parse_qs(raw, keep_blank_values=True))


class MockServer:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "MockServer":
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
