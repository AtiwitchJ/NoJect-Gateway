"""
PII Anonymizer and Masker (ISO/IEC 42001:2023 Control B.7.2 / OWASP LLM02:2025)
"""

import re
import unicodedata
from typing import Dict, Any, List
from .text_normalize import strip_zero_width

_ROMAN_DIGITS = str.maketrans({"Ⅰ": "1", "Ⅱ": "2", "Ⅲ": "3", "Ⅳ": "4", "Ⅴ": "5", "Ⅵ": "6", "Ⅶ": "7", "Ⅷ": "8", "Ⅸ": "9"})
_NUMBER_WORDS = {"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9"}
_NUMBER_WORD_RUN = re.compile(r"(?i)(?<!\w)(?:(?:zero|one|two|three|four|five|six|seven|eight|nine)[\s-]+){6,}(?:zero|one|two|three|four|five|six|seven|eight|nine)(?!\w)")
_SPLIT_SK = re.compile(r"\bsk-(?=(?:[A-Za-z0-9_-]\s*){10,})(?:[A-Za-z0-9_-]\s*){10,64}")

class PIIMasker:
    PATTERNS = {
        "THAI_NATIONAL_ID": (re.compile(r"\b\d{1}[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d{1}\b"), "[THAI_ID]"),
        "PHONE_NUMBER": (re.compile(r"(\+66|0)[2689]\d{1}[-\s]?\d{3}[-\s]?\d{4}\b"), "[PHONE_NUMBER]"),
        "EMAIL": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[EMAIL_REDACTED]"),
        "CREDIT_CARD": (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "[CREDIT_CARD]"),
        "API_KEY": (re.compile(r"\b(sk-[a-zA-Z0-9_-]{10,}|AKIA[0-9A-Z]{16})\b"), "[SECRET_KEY_REDACTED]"),
    }

    def _normalize(self, text: str) -> str:
        if not text:
            return ""
        normalized = strip_zero_width(text.translate(_ROMAN_DIGITS))
        normalized = unicodedata.normalize("NFKC", normalized)
        normalized = _NUMBER_WORD_RUN.sub(
            lambda match: "".join(_NUMBER_WORDS[word.lower()] for word in re.findall(r"[A-Za-z]+", match.group(0))),
            normalized,
        )
        return _SPLIT_SK.sub(lambda match: re.sub(r"\s+", "", match.group(0)), normalized)

    def mask(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"masked_text": text, "has_pii": False, "entities_found": []}

        masked = self._normalize(text)
        entities_found: List[str] = []

        for entity_type, (regex, replacement) in self.PATTERNS.items():
            if regex.search(masked):
                entities_found.append(entity_type)
                masked = regex.sub(replacement, masked)

        return {
            "masked_text": masked,
            "has_pii": len(entities_found) > 0,
            "entities_found": entities_found,
            "standard_code": "ISO/IEC 42001 B.7.2 / OWASP LLM02:2025"
        }
