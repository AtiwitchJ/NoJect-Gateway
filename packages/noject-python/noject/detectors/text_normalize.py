import base64
import binascii
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


def extract_hex_payloads(text: str, max_segments: int = 5) -> List[str]:
    """Find hex-encoded byte runs and decode printable ASCII/UTF-8 strings."""
    decoded: List[str] = []
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

