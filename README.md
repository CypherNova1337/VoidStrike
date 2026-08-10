# VoidStrike

**AI-assisted Remote Code Execution testing framework — a VoidSec-Hub project.**

VoidStrike hunts for, verifies, and documents remote-code-execution
vulnerabilities across the modern web attack surface: OS command injection,
server-side template injection, interpreted-language code injection, expression
language / JNDI (Log4Shell-class), insecure deserialization, and unrestricted
file upload. It backs every finding with a concrete oracle (reflected output,
timing, or an out-of-band callback), an optional LLM sharpens verdicts and
payloads, and a post-exploitation shell turns a confirmed injection into an
interactive command channel.

```
 __     __     _     _ ____  _        _ _
 \ \   / /__  (_) __| / ___|| |_ _ __(_) | _____
  \ \ / / _ \ | |/ _` \___ \| __| '__| | |/ / _ \
   \ V / (_) || | (_| |___) | |_| |  | |   <  __/
    \_/ \___/_/ |\__,_|____/ \__|_|  |_|_|\_\___|
```

---

## ⚠️ Authorized use only

VoidStrike sends **real attack payloads** to whatever you point it at. Use it
**only** on systems you own or are **explicitly authorized in writing** to test.
Unauthorized access to computer systems is illegal in most jurisdictions (U.S.
CFAA, U.K. Computer Misuse Act, and equivalents). You are solely responsible for
your use of this tool. See [`LICENSE`](LICENSE) and [`SECURITY.md`](SECURITY.md).

VoidStrike is built to keep you honest:

- it **refuses to run without a defined authorized scope** and rejects any host
  outside it,
- it requires you to **affirm authorization** before sending a single payload,
- it uses **non-destructive proofs of concept** (echo a marker, brief sleep, or
  OOB callback) — never destructive commands,
- it is **single-target focused** — no mass/internet-wide scanning, no
  self-propagation.

---

## Features

| Capability | Details |
|---|---|
| **6 RCE detection modules** | command injection, SSTI, code injection, expression-language/JNDI, deserialization, file upload |
| **Three oracles** | output-marker, time-based (blind), and out-of-band (OAST) confirmation |
| **AI assistance** | provider-agnostic LLM layer sharpens verdicts, expands payloads, and maps filter/WAF gaps — degrades to deterministic heuristics when offline |
| **Scope enforcement** | fail-closed guard with globs + CIDRs, out-of-scope carve-outs, hard blocklist, and an audit log |
| **Interactive shell** | derives a command channel from a confirmed injection — run commands, no re-fuzzing |
| **OAST** | local HTTP callback listener or a hosted collaborator domain for blind RCE |
| **Reporting** | JSON + Markdown reports with PoC payloads, evidence, and remediation |
| **Zero hard deps** | runs on the Python standard library; `httpx`/`PyYAML` used automatically if installed |

## Install

```bash
git clone https://github.com/CypherNova1337/RCE-Robot.git
cd RCE-Robot

# Runs as-is on Python 3.10+. Optional extras make it faster:
pip install -r requirements.txt          # httpx + PyYAML
# or install as a package (adds the `voidstrike` command):
pip install -e ".[all]"
```

No dependencies? It still works — `python -m voidstrike ...`.

## Quick start

1. **Define your authorized scope** (copy and edit the example):

   ```bash
   cp scope.example.yaml scope.yaml
   $EDITOR scope.yaml     # list ONLY hosts you are permitted to test
   ```

2. **Scan a target** (query parameters become injection points):

   ```bash
   python -m voidstrike scan \
     --scope scope.yaml \
     --url "https://app.example.com/ping?host=127.0.0.1" \
     --i-am-authorized
   ```

3. **Read the report** in `voidstrike-results/report.md` (and `report.json`).

List detection modules any time:

```bash
python -m voidstrike modules
```

## Usage

```
python -m voidstrike scan --scope scope.yaml [options]

  -u, --url URL          target URL (repeatable); query params = injection points
  -t, --targets FILE     YAML/JSON targets file (see targets.example.yaml)
  -m, --method METHOD    HTTP method for --url targets (default GET)
  -M, --modules ids      comma-separated module ids (default: all)
      --headers 'K: V'   extra header (repeatable)
      --test-headers     also fuzz common headers (User-Agent, X-Forwarded-For, ...)
      --rps N            max requests/second (be a good guest)
      --concurrency N    max concurrent requests
      --proxy URL        route through an intercepting proxy (e.g. Burp)
      --oob-domain D     OAST collaborator domain for blind checks
      --oob-listener P   start a local HTTP callback listener on port P
      --no-ai            disable the LLM layer (heuristics only)
  -o, --output DIR       report output directory
      --i-am-authorized  affirm written authorization (skips the prompt)
```

### Post-exploitation shell

After a scan confirms an output-based command/code injection, open a channel:

```bash
python -m voidstrike shell \
  --scope scope.yaml \
  --report voidstrike-results/report.json \
  --i-am-authorized
```

```
voidstrike:shell$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
voidstrike:shell$ uname -a
Linux web-01 5.15.0 ...
```

The channel is derived from the confirmed payload itself (the proven
`echo <marker>` slot is reused to wrap real command output), so it is reliable
and low-noise.

## AI configuration (provider-agnostic)

VoidStrike does not hard-code any AI vendor. Point it at any OpenAI-compatible
or messages-style HTTP endpoint via environment variables:

```bash
export VOIDSTRIKE_LLM_BASE_URL="https://your-llm-gateway.example/v1"
export VOIDSTRIKE_LLM_MODEL="your-model-id"
export VOIDSTRIKE_LLM_API_KEY="..."     # read from env, never written to disk
```

When configured, the AI layer:

- classifies ambiguous responses (executed / reflected / blocked / inconclusive),
- proposes additional context-aware payloads,
- suggests filter/WAF-evasion variants to map a client's coverage gaps,
- recommends the highest-value next step.

If no LLM is configured, VoidStrike runs fully on deterministic heuristics — the
AI never becomes a hard dependency, and it can never fabricate a "success" that
the marker/timing/OOB oracles don't independently support.

## Out-of-band (blind RCE)

Blind command injection, JNDI/Log4Shell, and deserialization are confirmed via
callbacks to infrastructure you control:

```bash
# Hosted collaborator (Interactsh-style) domain:
python -m voidstrike scan --scope scope.yaml -t targets.yaml \
    --oob-domain your-oast-domain.example --i-am-authorized

# Or a local listener when you control the network path:
python -m voidstrike scan --scope scope.yaml -t targets.yaml \
    --oob-listener 8000 --i-am-authorized
```

## Architecture

```
voidstrike/
├── authorization.py   scope guard + consent + audit (fail-closed)
├── http_client.py     async client, rate limiting, multipart, scope hook
├── config.py          runtime configuration
├── targets.py         URL / file → request templates
├── oob/               out-of-band interaction (OAST)
├── ai/                provider-agnostic LLM engine + analyzer + prompts
├── engine/            models, session/probe primitive, detector orchestrator
├── modules/           detection modules (auto-discovered)
│   ├── command_injection.py
│   ├── ssti.py
│   ├── code_injection.py
│   ├── expression_language.py   (OGNL / SpEL / JNDI Log4Shell)
│   ├── deserialization.py
│   └── file_upload.py
├── shell/             post-exploitation command channel + REPL
└── reporting/         JSON + Markdown reports
```

### Writing a module

Drop a file in `voidstrike/modules/` that subclasses `Module` and it is
auto-discovered:

```python
from voidstrike.modules.base import Module
from voidstrike.engine.models import Severity, Target

class MyModule(Module):
    name = "my_check"
    vuln_class = "My RCE Class"
    severity = Severity.CRITICAL

    async def run(self, target: Target) -> None:
        for point in target.injection_points():
            marker = self.marker()
            await self.try_payloads(point, [f"; echo {marker}"], marker)
```

## Testing

```bash
python -m pytest -q            # unit tests
python -m voidstrike modules   # sanity check discovery
```

The test suite spins up a deliberately vulnerable local server and confirms the
engine detects the injection end-to-end (no external network required).

## Disclaimer

This project is provided for lawful, authorized security testing and education
only. The authors accept no liability for misuse. Get permission. Stay in scope.
