# VoidStrike

Tests whether a web application can be made to run your code — and proves it when it can.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square)

## What it does

Remote code execution is the finding that ends the conversation. If input
reaches a shell, a template engine, a deserialiser or a file upload without the
right handling, an attacker stops reading data and starts running commands.

The trouble is that it hides in half a dozen unrelated shapes. Command injection
looks nothing like server-side template injection, which looks nothing like an
unsafe `pickle` load or a Log4Shell-style JNDI lookup. Each has its own payloads,
its own confirmation trick, and its own ways of being filtered. Testing all of
them by hand against every parameter is a long afternoon.

VoidStrike covers those classes in one pass. Behind it is a knowledge base of
RCE techniques, payloads and evasion transforms; it picks what to try for a
given parameter, judges whether the attempt actually executed, and adapts around
filters rather than repeating a payload that has already been blocked.

Confirmed findings are saved with the request that produced them, and `shell`
reopens a command channel from a saved finding so you can demonstrate impact
without reconstructing the attack by hand.

## Why you'd use it

- **Six RCE classes in one run** — command injection, SSTI, code injection,
  expression language and JNDI, insecure deserialisation, unrestricted upload.
- **Decides per request**, escalating and adapting rather than replaying a fixed
  list.
- **Out-of-band confirmation** for the cases that produce no visible output.
- **Scope files**, so a run can be restricted to hosts you're allowed to touch.
- **Reports with the reproducing request**, not just a claim.

## Install

```bash
git clone https://github.com/CypherNova1337/VoidStrike
cd VoidStrike
pip install -r requirements.txt
pip install .
```

Needs Python 3.8 or newer.

## Usage

```bash
voidstrike scan 'https://app.example/search?q=test'
```

Query parameters become injection points.

**Several targets, restricted to an agreed scope**

```bash
voidstrike scan -t targets.yaml -s scope.yaml -o reports/
```

Copy `scope.example.yaml` and `targets.example.yaml` to start from.

**Just one class of bug**

```bash
voidstrike modules                      # see what's available
voidstrike scan -u https://app.example/ -M ssti,cmdi
```

**Catch the blind cases**

```bash
voidstrike scan -u https://app.example/ --oob-domain abc.oast.fun
```

Some RCE returns nothing at all. Without an out-of-band channel you will miss
it.

**Test headers as well as parameters**

```bash
voidstrike scan -u https://app.example/ --test-headers
```

**Keep it gentle**

```bash
voidstrike scan -u https://app.example/ --rps 5 --concurrency 2
```

**Reopen a confirmed finding**

```bash
voidstrike shell
```

**See the technique library**

```bash
voidstrike brain
```

## Commands

| Command | What it's for |
|---|---|
| `scan` | Test target URLs for RCE |
| `modules` | List the detection modules |
| `brain` | Show the built-in technique and payload knowledge base |
| `shell` | Open a command channel from a saved finding |

### scan options

| Flag | Default | What it does |
|---|---|---|
| `urls` / `-u` | — | Target URL(s) |
| `-t` | — | YAML/JSON file describing targets |
| `-s` | — | Scope file restricting which hosts may be tested |
| `-m` | `GET` | HTTP method |
| `-M` | all | Comma-separated module ids |
| `--headers` | — | Extra header (repeatable) |
| `--test-headers` | off | Treat common headers as injection points |
| `--rps` | — | Max requests per second |
| `--concurrency` | — | Max concurrent requests |
| `--timeout` | — | Per-request timeout |
| `--proxy` | — | Proxy URL, e.g. Burp |
| `--insecure` | off | Disable TLS verification |
| `--oob-domain` | — | OAST collaborator domain |
| `--oob-listener` | — | Start a local HTTP callback listener on this port |
| `--no-ai` | off | Disable AI assistance |
| `-o` | — | Report output directory |

## Good to know

- **Confirming RCE means running a command on someone's server.** Even a harmless
  one is execution. Be sure that's in scope before you start, and keep what you
  run to the minimum that proves it.
- **Use the scope file.** It exists so a wildcard target list can't wander onto a
  host that was never in the engagement.
- **Without `--oob-domain` you will miss the blind cases**, which are a large
  share of real-world RCE.
- **Deserialisation and upload tests leave artefacts.** Files get written.
  Clean up, and tell the client what you left behind.
- **Filters aren't fixes.** Getting blocked means the WAF caught that payload,
  not that the underlying sink is safe.

## Authorised use

Only against systems you own or have explicit written permission to test. This
tool exists to execute code on remote machines; doing that without authorisation
is a serious criminal offence in essentially every jurisdiction. See
[SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
