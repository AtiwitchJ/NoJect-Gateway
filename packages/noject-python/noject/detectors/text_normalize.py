import base64
import binascii
import codecs
import re
import urllib.parse
from typing import List

_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
})

_ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF\u00AD\u200E\u200F\u202A-\u202E\u2060-\u2064\u180E\u034F]")


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


_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


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
        candidate = match.group(0)
        try:
            raw = base64.b64decode(candidate, validate=True)
            plain = raw.decode("utf-8")
        except Exception:
            continue
        if plain.isprintable() and len(plain.strip()) > 0:
            decoded.append(plain)
    return decoded


_HEX_RUN = re.compile(r"(?:(?:0x|\\x)?([0-9a-fA-F]{2})[\s,:-]?){8,}")


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

