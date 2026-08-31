"""
Shared text-canonicalization helpers used by PromptInjectionDetector and
JailbreakDetector to see through cheap, common obfuscation before the
keyword/regex patterns run. These do NOT replace a real semantic classifier
(see docs/superpowers/specs/2026-08-31-noject-gateway-design.md Phase 2) —
they close the specific gaps a red-team pass found the regex layer missing:
leetspeak substitution and base64-wrapped payloads.
"""
import base64
import re
from typing import List

_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
})


def deleetify(text: str) -> str:
    """Canonicalize common digit/symbol-for-letter substitutions
    (1gn0r3 -> ignore). Applied as an *additional* candidate for pattern
    matching, never in place of the original — callers should check both."""
    return text.translate(_LEET_MAP)


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
