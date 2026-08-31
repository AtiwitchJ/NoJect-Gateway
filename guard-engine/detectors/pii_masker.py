import re
from typing import Dict, Any, List, Tuple

class PIIMasker:
    """
    Detects and masks Personally Identifiable Information (PII) and Secrets.
    Aligned with ISO/IEC 42001 AI Data Privacy & Protection (Control B.7.2).
    """

    # Regex definitions for PII
    PATTERNS: List[Tuple[str, str, str]] = [
        # Thai National ID: 13 digits with or without hyphens
        ("THAI_ID", r"\b\d{1}[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d{1}\b", "[REDACTED_THAI_ID]"),
        # Credit Card: Visa, MasterCard, Amex, Discover (13-19 digits with separators)
        ("CREDIT_CARD", r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b", "[REDACTED_CREDIT_CARD]"),
        # Email address
        ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[REDACTED_EMAIL]"),
        # Phone Numbers: Thai (+66, 08x, 09x, 06x, 02x) and international format
        ("PHONE", r"\b(?:\+66|0)[2689]\d{1}[-\s]?\d{3}[-\s]?\d{4}\b|\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[REDACTED_PHONE]"),
        # API Keys and Secrets (OpenAI, GitHub, AWS, Generic Bearer)
        ("API_KEY", r"\b(sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})\b", "[REDACTED_API_KEY]"),
    ]

    def __init__(self):
        self.compiled = [
            (label, re.compile(pattern), placeholder)
            for label, pattern, placeholder in self.PATTERNS
        ]

    def mask(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"sanitized_text": "", "has_pii": False, "detected_entities": []}

        sanitized = text
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
