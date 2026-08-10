"""A deliberately-vulnerable local server used only by the test suite.

It SIMULATES command injection so tests never run a real shell: it reflects the
argument of an ``echo`` in the ``host`` parameter, and emulates ``$(cmd)``
substitution with canned output so the post-exploitation channel can be tested
end-to-end. Nothing here executes anything on the host.
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
    """Very small emulator: resolve echo of literals and $(cmd) substitutions."""
    m = re.search(r"echo\s+(.+)", value)
    if not m:
        return ""
    arg = m.group(1).strip().strip(";").strip("`").strip()

    def _sub(match: re.Match) -> str:
        cmd = match.group(1).split("2>&1")[0].strip()
        return _CANNED.get(cmd, f"[[{cmd}]]")

    arg = re.sub(r"\$\(([^)]*)\)", _sub, arg)
    return arg


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _respond(self, params: dict):
        host = params.get("host", [""])[0]
        reflected = _fake_shell(host)
        body = f"<html><body>PING result: {reflected}\n</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        params = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        self._respond(params)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode() if length else ""
        self._respond(parse_qs(raw, keep_blank_values=True))


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
