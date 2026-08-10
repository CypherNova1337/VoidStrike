# VoidStrike

**AI-assisted Remote Code Execution testing framework — a VoidSec-Hub project.**

VoidStrike hunts for, verifies, and documents remote-code-execution
vulnerabilities across the modern web attack surface: OS command injection,
server-side template injection, interpreted-language code injection, expression
language / JNDI (Log4Shell-class), insecure deserialization, and unrestricted
file upload.

At its core is **the Brain** — an always-on offensive intelligence with a
built-in knowledge base of every RCE manoeuvre (dozens of techniques, hundreds
of payloads, and an evasion-transform library). The Brain plans which manoeuvres
to run, judges whether each one executed, and adapts around filters — on every
request. It is not an optional add-on: with no configuration it reasons as a
deterministic expert system, and when you point it at an LLM endpoint it layers
live reasoning on top of that same expertise. Every finding is backed by a
concrete oracle (reflected output, timing, or an out-of-band callback), and a
post-exploitation shell turns a confirmed injection into an interactive command
channel.

```
 __     __     _     _ ____  _        _ _
 \ \   / /__  (_) __| / ___|| |_ _ __(_) | _____
  \ \ / / _ \ | |/ _` \___ \| __| '__| | |/ / _ \
   \ V / (_) || | (_| |___) | |_| |  | |   <  __/
    \_/ \___/_/ |\__,_|____/ \__|_|  |_|_|\_\___|
```

---

## ⚠️ Only use this on authorized targets. Unauthorized testing is illegal.

VoidStrike sends real attack payloads to whatever you point it at.

Optional: pass `--scope scope.yaml` to have VoidStrike enforce which hosts it may
touch during an engagement. It's off by default so the tool stays quick to use.

---

## Features

| Capability | Details |
|---|---|
| **The Brain** | always-on offensive intelligence: 34 manoeuvres / 140+ payloads / 7 evasion transforms built in; plans, judges and adapts on every request |
| **6 RCE detection modules** | command injection, SSTI, code injection, expression-language/JNDI, deserialization, file upload |
| **Three oracles** | output-marker, time-based (blind), and out-of-band (OAST) confirmation |
| **Optional LLM augmentation** | point the Brain at any OpenAI-compatible endpoint to add live reasoning on top of its built-in expertise — never a hard dependency |
| **Optional scope enforcement** | opt-in guard with globs + CIDRs, out-of-scope carve-outs, and an audit log |
| **Interactive shell** | derives a command channel from a confirmed injection — run commands, no re-fuzzing |
| **OAST** | local HTTP callback listener or a hosted collaborator domain for blind RCE |
| **Reporting** | JSON + Markdown reports with PoC payloads, evidence, and remediation |
| **Zero hard deps** | runs on the Python standard library; `httpx`/`PyYAML` used automatically if installed |

## Install

```bash
git clone https://github.com/CypherNova1337/VoidStrike.git
cd VoidStrike
pip install -e .        # adds the `voidstrike` command (Python 3.10+)
```

That's it — no required dependencies (`httpx`/`PyYAML` are used automatically if
present). If you'd rather not install, `python -m voidstrike ...` works too.

## Quick start

Just point it at a URL — query parameters become injection points:

```bash
voidstrike "https://app.example.com/ping?host=127.0.0.1"
```

That's it. The report lands in `voidstrike-results/report.md` (and `report.json`).

See what the Brain knows, or list modules:

```bash
voidstrike brain          # the full built-in manoeuvre knowledge base
voidstrike brain --class ssti
voidstrike modules
```

## Usage

```
voidstrike <url> [url...] [options]        # implicit scan
voidstrike scan <url> [url...] [options]   # explicit

  -t, --targets FILE     YAML/JSON targets file (see targets.example.yaml)
  -s, --scope FILE       OPTIONAL scope file to restrict which hosts may be hit
  -m, --method METHOD    HTTP method (default GET)
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
```

### Post-exploitation shell

After a scan confirms an output-based command/code injection, open a channel:

```bash
voidstrike shell --report voidstrike-results/report.json
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

## The Brain

The Brain is VoidStrike's core intelligence, and it is always on. Its long-term
memory is a built-in corpus of RCE manoeuvres (`voidstrike/ai/knowledge.py`) —
per-OS command-injection separators and evasions, per-engine SSTI, per-language
code injection and deserialization, OGNL/SpEL/JNDI, upload tricks, and a library
of evasion transforms. On every request the Brain:

- **plans** which manoeuvres to try, ranked to the observed context/stack,
- **judges** whether a payload executed (output / timing / OOB oracle),
- **adapts** around filters using its evasion transforms, and
- **recommends** the highest-value next move.

Inspect everything it knows with `voidstrike brain`.

### Optional LLM augmentation (provider-agnostic)

The Brain is fully operational with no LLM. To add live model reasoning on top
of its built-in expertise, point it at any OpenAI-compatible or messages-style
endpoint — VoidStrike hard-codes no vendor:

```bash
export VOIDSTRIKE_LLM_BASE_URL="https://your-llm-gateway.example/v1"
export VOIDSTRIKE_LLM_MODEL="your-model-id"
export VOIDSTRIKE_LLM_API_KEY="..."     # read from env, never written to disk
```

When augmented, the Brain additionally proposes context-specific payloads and
sharper verdicts. It can never fabricate a "success", though: an `executed`
verdict always requires a real oracle (marker echoed, timing, or OOB callback),
not model confidence.

## Out-of-band (blind RCE)

Blind command injection, JNDI/Log4Shell, and deserialization are confirmed via
callbacks to infrastructure you control:

```bash
# Hosted collaborator (Interactsh-style) domain:
voidstrike "https://app.example.com/" --oob-domain your-oast-domain.example

# Or a local listener when you control the network path:
voidstrike "https://app.example.com/" --oob-listener 8000
```

## Architecture

```
voidstrike/
├── authorization.py   optional scope guard + audit log
├── http_client.py     async client, rate limiting, multipart, scope hook
├── config.py          runtime configuration
├── targets.py         URL / file → request templates
├── oob/               out-of-band interaction (OAST)
├── ai/                the Brain + knowledge base + provider-agnostic LLM engine
│   ├── knowledge.py   built-in corpus of RCE manoeuvres + evasion transforms
│   ├── brain.py       always-on intelligence: plan / assess / evade / recommend
│   └── engine.py      optional LLM augmentation
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
voidstrike modules   # sanity check discovery
```

The test suite spins up a deliberately vulnerable local server and confirms the
engine detects the injection end-to-end (no external network required).

## Disclaimer

This project is provided for lawful, authorized security testing and education
only. The authors accept no liability for misuse. Get permission. Stay in scope.
