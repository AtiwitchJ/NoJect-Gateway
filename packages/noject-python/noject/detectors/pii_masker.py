"""
PII Anonymizer and Masker (ISO/IEC 42001:2023 Control B.7.2 / OWASP LLM02:2025)
"""

import re
from typing import Dict, Any, List

class PIIMasker:
    PATTERNS = {
        "THAI_NATIONAL_ID": (re.compile(r"\b\d{1}-?\d{4}-?\d{5}-?\d{2}-?\d{1}\b"), "[THAI_ID]"),
        "PHONE_NUMBER": (re.compile(r"(\+66|0)[689]\d{1}[-\s]?\d{3}[-\s]?\d{4}\b"), "[PHONE_NUMBER]"),
        "EMAIL": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[EMAIL_REDACTED]"),
        "CREDIT_CARD": (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "[CREDIT_CARD]"),
        "API_KEY": (re.compile(r"\b(sk-[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b"), "[SECRET_KEY_REDACTED]"),
    }

    def mask(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"masked_text": text, "has_pii": False, "entities_found": []}

        masked = text
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
