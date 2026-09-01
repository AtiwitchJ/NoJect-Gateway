import re
import unicodedata
from typing import Dict, Any, List, Tuple

# Zero-width and other invisible formatting characters. Inserting one of
# these mid-value (089-123<ZWSP>-4567) leaves the text visually identical
# but breaks every regex below, so they are stripped before matching.
_INVISIBLE_CHARS = re.compile(
    "["
    "​‌‍"  # zero-width space / non-joiner / joiner
    "⁠"              # word joiner
    "﻿"              # zero-width no-break space (BOM)
    "­"              # soft hyphen
    "᠎"              # Mongolian vowel separator
    "]"
)
_ROMAN_DIGITS = str.maketrans({"Ⅰ": "1", "Ⅱ": "2", "Ⅲ": "3", "Ⅳ": "4", "Ⅴ": "5", "Ⅵ": "6", "Ⅶ": "7", "Ⅷ": "8", "Ⅸ": "9"})
_NUMBER_WORDS = {"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9"}
_NUMBER_WORD_RUN = re.compile(r"(?i)(?<!\w)(?:(?:zero|one|two|three|four|five|six|seven|eight|nine)[\s-]+){6,}(?:zero|one|two|three|four|five|six|seven|eight|nine)(?!\w)")
_SPLIT_SK = re.compile(r"\bsk-(?=(?:[A-Za-z0-9_-]\s*){10,})(?:[A-Za-z0-9_-]\s*){10,64}")


def normalize_for_matching(text: str) -> str:
    """Canonicalize text before PII pattern matching.

    Applies NFKC normalization (folding Unicode confusables and fullwidth
    digits such as ０８９ back to their ASCII forms) and removes invisible
    formatting characters. Without this, trivially obfuscated values slip
    past the patterns while remaining perfectly readable to a human or a
    downstream model.
    """
    if not text:
        return text
    normalized = _INVISIBLE_CHARS.sub("", text.translate(_ROMAN_DIGITS))
    normalized = unicodedata.normalize("NFKC", normalized)
    normalized = _NUMBER_WORD_RUN.sub(
        lambda match: "".join(_NUMBER_WORDS[word.lower()] for word in re.findall(r"[A-Za-z]+", match.group(0))),
        normalized,
    )
    return _SPLIT_SK.sub(lambda match: re.sub(r"\s+", "", match.group(0)), normalized)


class PIIMasker:
    """
    Detects and masks Personally Identifiable Information (PII) and Secrets.
    Aligned with ISO/IEC 42001 AI Data Privacy & Protection (Control B.7.2).
    """

    # Regex definitions for PII.
    #
    # ORDER MATTERS: patterns are applied in sequence and each replaces the
    # text it matched, so the most specific patterns must run first. API keys
    # contain long digit runs, and a numeric pattern running earlier would
    # consume part of the key and leave the rest exposed
    # ("sk-proj-[REDACTED_PHONE]abcdef") instead of redacting the secret.
    PATTERNS: List[Tuple[str, str, str]] = [
        # API Keys and Secrets — first: most specific, and the highest-impact
        # thing to lose.
        ("API_KEY", r"\b(sk-[a-zA-Z0-9_-]{10,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})\b", "[REDACTED_API_KEY]"),
        # Thai National ID: 13 digits with or without hyphens
        # Separators may be hyphen, space, dot, or slash — people write Thai
        # IDs every one of those ways, and pinning the pattern to [-\s] let
        # "1/1002/00345/67/8" through unmasked.
        ("THAI_ID", r"\b\d{1}[-.\s/]?\d{4}[-.\s/]?\d{5}[-.\s/]?\d{2}[-.\s/]?\d{1}\b", "[REDACTED_THAI_ID]"),
        # Credit Card: Visa, MasterCard, Amex, Discover (13-19 digits with separators)
        # 13-19 digits: the ISO/IEC 7812 PAN range. The old pattern hard-coded
        # 16 digits with a trailing \b, so a 19-digit UnionPay/Visa number
        # matched nothing at all (the \b failed mid-number).
        ("CREDIT_CARD", r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", "[REDACTED_CREDIT_CARD]"),
        # Email address
        ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[REDACTED_EMAIL]"),
        # Phone Numbers: Thai (+66, 08x, 09x, 06x, 02x) and international format
        # NOTE the leading (?<!\d) instead of \b. "\b\+66" can never match:
        # \b requires a word/non-word transition, but a space followed by "+"
        # is non-word to non-word — so every international-format number
        # written as "+66812345678" slipped through entirely.
        # Separators are also optional throughout, since Thai numbers are
        # commonly written with no hyphens at all.
        # The lookarounds exclude adjacent alphanumerics, not just digits, so
        # a digit run embedded in an identifier or token is not mistaken for
        # a phone number.
        # The Thai branch allows a separator after the country/trunk code
        # too: "+66 81 234-5678" is how the number is normally written by
        # hand, and requiring the first group to be contiguous missed it.
        ("PHONE", r"(?<![\w])(?:\+66|0)[-.\s]?[2689][-.\s]?\d[-.\s]?\d{3}[-.\s]?\d{4}(?![\w])|(?<![\w+])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?![\w])", "[REDACTED_PHONE]"),
    ]

    def __init__(self):
        self.compiled = [
            (label, re.compile(pattern), placeholder)
            for label, pattern, placeholder in self.PATTERNS
        ]

    def mask(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"sanitized_text": "", "has_pii": False, "detected_entities": []}

        # Match against the normalized form. The normalized text is also what
        # gets forwarded: returning the original would re-introduce the very
        # bytes that evaded matching, leaving the PII unmasked downstream.
        sanitized = normalize_for_matching(text)
        detected = []

        for label, pattern, placeholder in self.compiled:
            matches = pattern.findall(sanitized)
            if matches:
                detected.append({
                    "type": label,
                    "count": len(matches),
                })
                sanitized = pattern.sub(placeholder, sanitized)

        return {
            "sanitized_text": sanitized,
            "has_pii": len(detected) > 0,
            "detected_entities": detected,
        }
