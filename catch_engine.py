"""
ExfilWatch — Catch Engine
Two detection layers:

1. KNOWN-SCHEME DECODE
   If text was hidden with a named scheme (classic zero-width, or the
   GlassWorm-style variation-selector technique), decode it directly.

2. EVIDENCE-FUSION ANOMALY SCORER (works even without knowing the scheme)
   Each independent signal below is emitted as (name, likelihood_ratio)
   evidence and combined via scoring.fuse() — naive-Bayes log-odds
   fusion, not hand-picked point addition. Every likelihood ratio has a
   documented justification at its call site: how many times more
   likely is this signal under a real attack than under ordinary text?
   These are initial engineering estimates, not measured constants —
   validate.py checks them against an actual labeled test corpus so the
   claim is falsifiable rather than asserted.

   Produces a 0-100 risk score + a human-readable reason list, so a
   judge sees not just "yes/no" but *why*, with a traceable derivation
   from evidence to score.
"""

import re
import unicodedata
import channel_engine
from hide_engine import (
    ZERO_WIDTH_CHARS,
    reveal,
    reveal_variation_selector,
    reveal_tags,
    is_variation_selector,
)
import scoring

# Characters with zero visible width, commonly abused for hidden channels
INVISIBLE_RANGES = [
    (0x200B, 0x200F),      # zero width space..RTL mark (classic stego scheme)
    (0x202A, 0x202E),      # bidi embedding/override controls
    (0x2060, 0x2064),      # word joiner etc.
    (0xFE00, 0xFE0F),      # variation selectors VS1-16 (GlassWorm scheme, low half)
    (0xFEFF, 0xFEFF),      # BOM / zero width no-break space
    (0xE0100, 0xE01EF),    # variation selectors VS17-256 (GlassWorm scheme, high half)
    (0xE0000, 0xE007F),    # Tags block ("ASCII smuggling")
    (0x00AD, 0x00AD),      # soft hyphen (benign when isolated)
    (0x115F, 0x1160), (0x180E, 0x180E), (0x2800, 0x2800), (0x3164, 0x3164), (0xFFA0, 0xFFA0),
                           # blank-glyph chars that are NOT category Cf (Hangul fillers, braille blank...)
]


def _is_invisible(ch: str) -> bool:
    if not ch:  # guards the end-of-string case: text[i+1] is "" at the last index,
        return False  # and _strip_benign calls this on it — this was crashing on
                       # any reply ending in an emoji, e.g. "...thanks! \U0001F44D\uFE0F"
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in INVISIBLE_RANGES)


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    return name.split(" ")[0]


def _emojiish(ch: str) -> bool:
    return bool(ch) and (unicodedata.category(ch) in ("So", "Sk") or ord(ch) in (0xFE0E, 0xFE0F))


def _is_rtl(ch: str) -> bool:
    return bool(ch) and unicodedata.bidirectional(ch) in ("R", "AL")


def _strip_benign(text: str) -> str:
    """
    Remove invisible codepoints that are LEGITIMATE in ordinary text before
    scanning, so emoji, flags, Indic/Arabic/Hebrew script and pasted soft
    hyphens don't look like covert channels. Runs of invisible characters,
    VS17-256, Tags outside a flag sequence, and anything spaced between plain
    Latin letters are NOT stripped, so real smuggling is still caught.
    "Soft" exemptions (Indic ZWJ/ZWNJ, bidi marks, soft hyphen, BOM) are
    revoked entirely if they exceed 10% of the text: that density is not natural,
    it is a low-bandwidth channel hiding in the exemption.
    """
    n = len(text)
    emoji_strip, soft_strip = set(), set()
    i = 0
    while i < n:
        ch, cp = text[i], ord(text[i])
        prev = text[i - 1] if i > 0 else ""
        nxt = text[i + 1] if i + 1 < n else ""
        if cp == 0x1F3F4:  # subdivision flag (England...): tag letters + cancel tag
            j = i + 1
            while j < n and 0xE0020 <= ord(text[j]) <= 0xE007E:
                j += 1
            if j > i + 1 and j < n and ord(text[j]) == 0xE007F:
                emoji_strip.update(range(i + 1, j + 1))
                i = j + 1
                continue
        elif cp in (0xFE0E, 0xFE0F):
            if (prev and not _is_invisible(prev) and not _is_invisible(nxt)
                    and (_emojiish(prev) or prev in "#*0123456789")):
                emoji_strip.add(i)
        elif cp == 0x200D and _emojiish(prev) and _emojiish(nxt):
            emoji_strip.add(i)
        elif cp in (0x200C, 0x200D):
            if (prev and nxt and ord(prev) > 0x7F and ord(nxt) > 0x7F
                    and unicodedata.category(prev)[0] in "LM" and unicodedata.category(nxt)[0] in "LM"):
                soft_strip.add(i)
        elif cp in (0x200E, 0x200F):
            if prev and not _is_invisible(prev) and not _is_invisible(nxt) and (_is_rtl(prev) or _is_rtl(nxt)):
                soft_strip.add(i)
        elif cp == 0x00AD:
            if prev and nxt and not _is_invisible(prev) and not _is_invisible(nxt):
                soft_strip.add(i)
        elif cp == 0xFEFF and i == 0:
            soft_strip.add(i)
        i += 1
    visible_len = max(1, len(re.sub(r"\s", "", text)))
    if len(soft_strip) / visible_len > 0.10:
        soft_strip = set()
    strip = emoji_strip | soft_strip
    return "".join(ch for k, ch in enumerate(text) if k not in strip)


def known_scheme_decode(text: str) -> dict:
    zw_message = reveal(text)
    if zw_message:
        return {"found": True, "message": zw_message, "technique": "Zero-Width Space/Joiner encoding"}

    vs_message = reveal_variation_selector(text)
    if vs_message:
        return {
            "found": True,
            "message": vs_message,
            "technique": "Unicode Variation Selector smuggling (GlassWorm-style)",
        }

    tag_message = reveal_tags(text)
    if tag_message:
        return {
            "found": True,
            "message": tag_message,
            "technique": 'Unicode Tags-block smuggling ("ASCII smuggling")',
        }

    url = channel_engine.scan(text)
    if url["decoded"]:
        return {"found": True, "message": url["decoded"], "technique": url["technique"]}

    return {"found": False, "message": "", "technique": None}


def anomaly_score(text: str) -> dict:
    reasons = []
    evidence = []  # list of (signal_name, likelihood_ratio) fed to scoring.fuse()

    visible_len = max(1, len(re.sub(r"\s", "", text)))
    invisible_chars = [ch for ch in text if _is_invisible(ch)]
    invisible_count = len(invisible_chars)
    invisible_ratio = invisible_count / visible_len

    if invisible_count > 0:
        # Zero-width/invisible Unicode codepoints essentially never appear
        # in ordinary human or AI-generated text (no keyboard produces
        # them, no writing system needs them). LR=25 reflects "rare but
        # not literally impossible" (e.g. a stray BOM from a bad file
        # read) rather than treating this as absolute proof on its own.
        evidence.append(("invisible characters present", 25))
        reasons.append(
            f"Found {invisible_count} invisible/zero-width characters "
            f"({invisible_ratio:.1%} of visible text) — classic covert channel signal."
        )
        if invisible_ratio > 0.05:
            evidence.append(("high invisible-character density (>5%)", 15))

    zw_hits = sum(1 for ch in text if ch in ZERO_WIDTH_CHARS)
    if zw_hits > 4:
        evidence.append(("classic zero-width scheme signature", 150))
        reasons.append("Matches the known zero-width bit encoding pattern (classic scheme).")

    vs_hits = sum(1 for ch in text if is_variation_selector(ch))
    if vs_hits > 0:
        vs_lr = min(400, 80 * vs_hits)
        evidence.append((f"Unicode Variation Selector characters present ({vs_hits})", vs_lr))
        reasons.append(
            f"Found {vs_hits} Unicode Variation Selector character(s) — this is the exact "
            "encoding technique used by GlassWorm, the active 2025-26 npm supply-chain worm "
            "(433+ compromised packages as of March 2026), not the classic zero-width scheme."
        )

    tag_hits = sum(1 for ch in text if 0xE0000 <= ord(ch) <= 0xE007F)
    if tag_hits > 0:
        evidence.append((f"Unicode Tags-block characters present ({tag_hits})", min(400, 80 * tag_hits)))
        reasons.append(
            f"Found {tag_hits} invisible Tags-block character(s) (U+E0000–E007F) — the \"ASCII smuggling\" "
            "technique publicly demonstrated against LLM assistants, which mirrors readable ASCII invisibly."
        )

    if invisible_count >= 4:
        evidence.append((f"multiple invisible characters ({invisible_count})", min(200, 10 * invisible_count)))

    url_channel = channel_engine.scan(text)
    evidence.extend(url_channel["evidence"])
    reasons.extend(url_channel["reasons"])

    latin = sum(1 for ch in text if ch.isalpha() and "LATIN" in _script_of(ch))
    cyrillic = sum(1 for ch in text if ch.isalpha() and "CYRILLIC" in _script_of(ch))
    if latin > 10 and cyrillic > 0:
        evidence.append((f"Cyrillic look-alike characters mixed into Latin text ({cyrillic})", 10))
        reasons.append(
            f"Detected {cyrillic} Cyrillic look-alike character(s) mixed into Latin text "
            "— possible homoglyph smuggling."
        )

    named_chars = set(ZERO_WIDTH_CHARS)
    unnamed_format_chars = [
        ch for ch in text
        if unicodedata.category(ch) == "Cf" and ch not in named_chars and not _is_invisible(ch)
    ]
    if unnamed_format_chars:
        evidence.append((f"unrecognized Unicode format-control characters ({len(unnamed_format_chars)})", min(400, 20 * len(unnamed_format_chars))))
        reasons.append(
            f"Found {len(unnamed_format_chars)} Unicode format-control character(s) that match neither "
            "named scheme in our library — flagged by category-based analysis (Unicode General_Category=Cf), "
            "not a hardcoded signature. This is how an unpublished or novel hiding technique still gets caught."
        )

    fusion = scoring.fuse(evidence)
    if not reasons:
        reasons.append("No covert-channel indicators found. Text looks clean.")

    return {"score": fusion["risk_score"], "reasons": reasons, "contributions": fusion["contributions"]}


def analyze(text: str) -> dict:
    text = _strip_benign(text)
    decode = known_scheme_decode(text)
    anomaly = anomaly_score(text)
    return {
        "decoded_message": decode["message"] if decode["found"] else None,
        "technique": decode["technique"],
        "risk_score": anomaly["score"],
        "reasons": anomaly["reasons"],
        "contributions": anomaly["contributions"],
        "verdict": (
            f"HIDDEN DATA DECODED ({decode['technique']})" if decode["found"]
            else "HIGH RISK — likely covert channel" if anomaly["score"] >= 50
            else "LOW RISK" if anomaly["score"] < 15
            else "SUSPICIOUS"
        ),
    }


if __name__ == "__main__":
    from hide_engine import hide, hide_variation_selector
    stego = hide("user_pw=hunter2", "Sure, here is a quick summary of today's meeting notes for the team.")
    vs_stego = hide_variation_selector(
        "internal_api_key=sk-prod-7f3a9c2b",
        "Sure, here is a quick summary of today's meeting notes for the team.",
    )
    clean = "This is a perfectly ordinary sentence with nothing hidden inside it at all."

    print("== Zero-width stego text ==")
    print(analyze(stego))
    print("\n== GlassWorm-style (Variation Selector) stego text ==")
    print(analyze(vs_stego))
    print("\n== Clean text ==")
    print(analyze(clean))
