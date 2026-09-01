import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse
from typing import List

_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
})

_ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF\u00AD\u200E\u200F\u202A-\u202E\u2060-\u2064\u180E\u034F]")
_UNICODE_ESCAPE = re.compile(r"\\u(?:\{([0-9a-fA-F]{1,6})\}|([0-9a-fA-F]{4}))")


def deleetify(text: str) -> str:
    """Canonicalize common digit/symbol-for-letter substitutions
    (1gn0r3 -> ignore). Applied as an *additional* candidate for pattern
    matching, never in place of the original — callers should check both."""
    return text.translate(_LEET_MAP)


def strip_zero_width(text: str) -> str:
    """Remove invisible zero-width and bidirectional formatting characters
    that attackers use to break contiguous regex matching across words/numbers."""
    if not text:
        return ""
    return _ZERO_WIDTH_PATTERN.sub("", text)


# Confusables that NFKC does NOT fold, because they are genuinely distinct
# codepoints — Cyrillic/Greek letters that render identically to Latin ones.
# A model reads "іgnore" (Cyrillic і) as "ignore"; a regex does not.
_CONFUSABLES = str.maketrans({
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g", "ⅼ": "l",
    "ь": "b", "г": "r", "т": "t", "м": "m", "к": "k", "н": "h", "в": "b",
    # Greek lowercase — omicron in "ignοre" is the classic one, and it was
    # missing while only the uppercase forms were mapped.
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "μ": "u", "σ": "o", "γ": "y",
    # Greek uppercase
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Misc
    "ı": "i", "İ": "I", "ｌ": "l", "ɑ": "a", "ᴏ": "o", "ѐ": "e",
})


def normalize_unicode(text: str) -> str:
    """Fold Unicode variants to their ASCII skeleton before matching.

    Two separate problems:
      - NFKC handles compatibility forms: fullwidth (ｉｇｎｏｒｅ), ligatures,
        superscripts, and non-breaking spaces.
      - NFKC deliberately does NOT fold visually-identical characters from
        other scripts, since Cyrillic "о" really is a different letter from
        Latin "o". Those need an explicit confusables table.

    A model reads both forms as the intended word, so the filter must too.
    """
    if not text:
        return ""
    # Decode Unicode TAG characters (U+E0020..U+E007E) to the ASCII they
    # invisibly encode. Also accept the historical malformed probe spelling
    # U+E006 followed by "9", which was intended to represent U+E0069.
    text = text.replace("\ue0069", "i")
    text = "".join(
        chr(ord(ch) - 0xE0000) if 0xE0020 <= ord(ch) <= 0xE007E else "" if ord(ch) == 0xE007F else ch
        for ch in text
    )
    normalized = unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)
    # NFKC composes i + COMBINING ACUTE into í. A model still reads that as
    # "ignore", so create an accent-insensitive security skeleton.
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", normalized)
        if unicodedata.category(ch) != "Mn"
    )


def decode_unicode_escapes(text: str) -> str:
    """Decode JavaScript/JSON-style literal Unicode escapes without using
    unicode_escape on the whole string (which can corrupt real Unicode)."""
    def replace(match: re.Match) -> str:
        value = int(match.group(1) or match.group(2), 16)
        if value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
            return match.group(0)
        return chr(value)
    return _UNICODE_ESCAPE.sub(replace, text)


def decode_html_entities(text: str) -> str:
    """Decode named and numeric HTML entities to a bounded fixed point."""
    current = text
    for _ in range(3):
        nxt = html.unescape(current)
        if nxt == current:
            break
        current = nxt
    return current


def rot13(text: str) -> str:
    """ROT13-decode text. Costs an attacker nothing to apply and defeats
    every literal keyword pattern; ROT13 is its own inverse, so a single
    transform covers both directions."""
    if not text:
        return ""
    try:
        return codecs.decode(text, "rot_13")
    except Exception:
        return text


# "i g n o r e   a l l" — single characters separated by spaces/punctuation.
# Requires a run of at least 6 to avoid collapsing ordinary short words.
_SPACED_LETTERS = re.compile(r"(?:\b[A-Za-z]\b[\s.\-_*|]+){5,}\b[A-Za-z]\b")


def collapse_spaced_letters(text: str) -> str:
    """Collapse s-p-e-l-l-e-d o-u-t runs back into words.

    Spacing out a phrase leaves it perfectly readable to a model while
    breaking every \\b-anchored keyword pattern. Only runs of 6+ single
    letters are collapsed, so ordinary prose ("I a m" or initialisms) is
    left alone.

    Word boundaries are preserved: in "i g n o r e   a l l", letters are
    separated by a single space and words by a wider gap, so single
    separators are removed while runs of 2+ collapse to one space. Removing
    every separator would yield "ignoreall...", which matches no
    whitespace-anchored pattern either.
    """
    if not text:
        return ""

    def _join(match: re.Match) -> str:
        chunk = match.group(0)
        if re.search(r"[.\-_*|]", chunk):
            # Punctuation is doing the intra-word spacing
            # ("i-g-n-o-r-e a-l-l"), so whitespace marks word boundaries.
            chunk = re.sub(r"\s+", "\x00", chunk)
            chunk = re.sub(r"[.\-_*|]", "", chunk)
        else:
            # Whitespace-only spacing ("i g n o r e   a l l"): a single
            # space separates letters, a wider gap separates words.
            chunk = re.sub(r"\s{2,}", "\x00", chunk)
            chunk = re.sub(r"\s", "", chunk)
        return chunk.replace("\x00", " ")

    return _SPACED_LETTERS.sub(_join, text)


def url_unescape_text(text: str) -> str:
    """Unescape URL percent-encoded sequences to uncover encoded tokens."""
    if not text or "%" not in text:
        return text
    try:
        return urllib.parse.unquote(text)
    except Exception:
        return text


_BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/][ \t\r\n]*){16,}={0,2}(?![A-Za-z0-9+/=])")


def extract_base64_payloads(text: str, max_segments: int = 5) -> List[str]:
    """Find base64-looking substrings and decode the ones that are valid
    base64 AND decode to printable text. Attackers wrap an instruction-
    override payload in base64 specifically to hide it from keyword
    matching; the gateway must inspect what the model will actually see
    once something downstream decodes it, not just the encoded wrapper."""
    decoded: List[str] = []
    for match in _BASE64_RUN.finditer(text):
        if len(decoded) >= max_segments:
            break
        candidate = re.sub(r"\s+", "", match.group(0))
        try:
            raw = base64.b64decode(candidate, validate=True)
            plain = raw.decode("utf-8")
        except Exception:
            continue
        if plain.isprintable() and len(plain.strip()) > 0:
            decoded.append(plain)
    return decoded


_HEX_RUN = re.compile(r"(?:(?:0x|\\x)?([0-9a-fA-F]{2})[\s,:-]?){8,}")


def normalization_views(text: str, max_views: int = 48) -> List[tuple]:
    """Yield (label, text) alternate readings of one candidate.

    Obfuscations compose — an attacker writes "1𝐠𝐧𝐨𝐫𝐞" (math-bold AND
    leetspeak), or percent-encodes a phrase, or base64-wraps a hex string.
    Enumerating a fixed list of single transforms and a couple of
    hand-picked pairs misses every combination not on the list, which is
    how "math-bold leet hybrid", "url-encoded ignore", and "hex then
    base64 nested" all slipped through.

    So: build views by applying the cheap character-level normalizers
    CUMULATIVELY, and decode encoded payloads RECURSIVELY to a bounded
    depth. The attacker can layer transforms freely; the defender has to
    unwrap them the same way.
    """
    views: List[tuple] = []
    seen = {text}

    def add(label: str, value: str) -> None:
        if value and value not in seen and len(views) < max_views:
            seen.add(value)
            views.append((label, value))

    # Cumulative character-level normalization. Each step is applied on top
    # of the previous, so a payload combining several is still resolved.
    stages = [
        ("unicode-escape decoding", decode_unicode_escapes),
        ("HTML-entity decoding", decode_html_entities),
        ("url-decoding", url_unescape_text),
        ("unicode/homoglyph normalization", normalize_unicode),
        ("zero-width stripping", strip_zero_width),
        ("spaced-letter collapse", collapse_spaced_letters),
        ("leetspeak normalization", deleetify),
    ]
    current = text
    labels: List[str] = []
    # Repeat the chain so entity-encoded Unicode escapes and URL-encoded
    # entities are resolved regardless of wrapper order.
    for _ in range(3):
        changed = False
        for label, fn in stages:
            nxt = fn(current)
            if nxt != current:
                labels.append(label)
                current = nxt
                add(" + ".join(labels), current)
                changed = True
        if not changed:
            break

    # ROT13 is not cumulative — it is an involution, so applying it to an
    # already-normalized view is the useful form, not part of the chain.
    add("ROT13 decoding", rot13(text))
    if current != text:
        add("ROT13 decoding (normalized)", rot13(current))

    # Recursive decoding: base64 of hex, hex of base64, and so on. Bounded
    # depth keeps this from becoming a decompression bomb.
    def decode_layer(source: str, depth: int, trail: str) -> None:
        if depth <= 0 or len(views) >= max_views:
            return
        for label, decoder in (
            ("base64", extract_base64_payloads),
            ("hex", extract_hex_payloads),
        ):
            for decoded in decoder(source):
                path = f"{trail}->{label}" if trail else label
                add(f"{path}-decoded payload", decoded)
                normalized = decoded
                for _, fn in stages:
                    normalized = fn(normalized)
                add(f"{path}-decoded + normalized", normalized)
                # ROT13 inside an encoded wrapper is a common double-wrap
                # ("base64 of ROT13"); it is an involution so it never
                # appears in the cumulative chain above and must be tried
                # explicitly on each decoded layer.
                rotated = rot13(decoded)
                add(f"{path}-decoded + ROT13", rotated)
                decode_layer(decoded, depth - 1, path)
                decode_layer(normalized, depth - 1, path + "->normalized")
                decode_layer(rotated, depth - 1, path + "->rot13")

    decode_layer(text, 3, "")
    if current != text:
        decode_layer(current, 2, "normalized")
    decode_layer(rot13(text), 3, "rot13")

    return views


def extract_hex_payloads(text: str, max_segments: int = 5) -> List[str]:
    """Find hex-encoded byte runs and decode printable ASCII/UTF-8 strings."""
    decoded: List[str] = []
    # Find consecutive hex runs (at least 16 hex chars / 8 bytes)
    raw_hex_matches = re.finditer(r"\b(?:[0-9a-fA-F]{2}){8,}\b", text)
    for match in raw_hex_matches:
        if len(decoded) >= max_segments:
            break
        candidate = match.group(0)
        try:
            raw = bytes.fromhex(candidate)
            plain = raw.decode("utf-8", errors="ignore")
            if plain.isprintable() and len(plain.strip()) > 0:
                decoded.append(plain)
        except Exception:
            continue
    return decoded
