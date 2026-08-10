"""Unrestricted file upload -> webshell detection.

When a target declares an ``upload_field`` (and optionally ``upload_url_bases``
where uploads become web-accessible), this module attempts to upload a
**benign marker shell** in several server languages, then requests it back and
checks for the success marker. The uploaded file only echoes a random token —
it does not expose an interactive shell to the world — and every candidate is
tracked so the tester can clean them up afterwards (see the run report).

If the target does not declare an upload field this module is a no-op.
"""

from __future__ import annotations

import secrets

from ..engine.models import Confidence, Finding, Severity, Target
from ..http_client import Response
from .base import Module


class FileUpload(Module):
    name = "file_upload"
    vuln_class = "Unrestricted File Upload (RCE)"
    severity = Severity.CRITICAL
    remediation = (
        "Validate uploads by content, not just extension; store them outside the "
        "web root or on a separate domain served without execution; randomise "
        "stored names; and disable script execution in upload directories."
    )

    def _shells(self, marker: str) -> list[tuple[str, str, str]]:
        """Return (filename, content, content_type) benign marker shells."""
        rid = secrets.token_hex(3)
        return [
            (f"vs_{rid}.php", f"<?php echo '{marker}'; ?>", "application/x-php"),
            (f"vs_{rid}.php5", f"<?php echo '{marker}'; ?>", "application/x-php"),
            (f"vs_{rid}.phtml", f"<?php echo '{marker}'; ?>", "application/x-php"),
            (f"vs_{rid}.jsp", f"<% out.print(\"{marker}\"); %>", "application/octet-stream"),
            (f"vs_{rid}.asp", f"<% Response.Write(\"{marker}\") %>", "application/octet-stream"),
            (f"vs_{rid}.aspx",
             '<%@ Page Language="C#" %><% Response.Write("' + marker + '"); %>',
             "application/octet-stream"),
            # Double-extension / content-type confusion probes.
            (f"vs_{rid}.php.jpg", f"<?php echo '{marker}'; ?>", "image/jpeg"),
            (f"vs_{rid}.php%00.jpg", f"<?php echo '{marker}'; ?>", "image/jpeg"),
        ]

    async def run(self, target: Target) -> None:
        if not target.upload_field:
            return
        marker = self.marker()
        for filename, content, ctype in self._shells(marker):
            resp = await self.s.http.request(
                target.method or "POST", target.url,
                data=dict(target.upload_extra) or None,
                files={target.upload_field: (filename, content, ctype)},
                headers=target.headers or None,
            )
            if not resp.ok:
                continue
            # Direct reflection of the marker in the upload response (rare but possible).
            located = await self._locate(target, filename, marker, resp)
            if located:
                return

    async def _locate(self, target: Target, filename: str, marker: str,
                      upload_resp: Response) -> bool:
        bases = list(target.upload_url_bases)
        # If the upload response echoes a path to the file, try that too.
        if filename in upload_resp.text:
            bases.append(self._guess_from_response(target.url, upload_resp.text, filename))
        for base in filter(None, bases):
            url = base.replace("{name}", filename) if "{name}" in base else base.rstrip("/") + "/" + filename
            try:
                r = await self.s.http.get(url)
            except Exception:  # noqa: BLE001 - scope guard may reject
                continue
            if marker in r.text:
                finding = Finding(
                    vuln_class=self.vuln_class,
                    module=self.name,
                    injection_point=f"upload:{target.upload_field}",
                    url=target.url,
                    method=target.method or "POST",
                    payload=f"uploaded {filename} -> {url}",
                    severity=self.severity,
                    confidence=Confidence.CONFIRMED,
                    marker=marker,
                    evidence=f"marker returned from {url}",
                    oracle="output",
                    response_status=r.status,
                    remediation=self.remediation,
                    ai_signal="uploaded benign marker shell executed on retrieval",
                    request_summary=f"upload {filename} then GET {url}",
                )
                self.s.record(finding)
                self.log.warning(
                    f"[file_upload] REMEMBER TO REMOVE the test file left at {url}"
                )
                return True
        return False

    @staticmethod
    def _guess_from_response(base_url: str, text: str, filename: str) -> str:
        from urllib.parse import urljoin

        idx = text.find(filename)
        start = text.rfind('"', 0, idx)
        start = start if start != -1 else text.rfind("'", 0, idx)
        end = idx + len(filename)
        path = text[start + 1 : end] if start != -1 else filename
        path = path.strip().lstrip("(=")
        return urljoin(base_url, path)
