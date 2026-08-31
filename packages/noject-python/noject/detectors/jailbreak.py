"""
Jailbreak & Adversarial Persona Detector (MITRE AML.T0051 / OWASP LLM01:2025)
"""

import re
from typing import Dict, Any

class JailbreakDetector:
    JAILBREAK_PATTERNS = [
        r"(?i)\b(DAN|Do\s+Anything\s+Now|DUDE|STAN|Mongo\s+Tom|AIM|KEVIN|Omega)\b.*?\b(broken\s+free|no\s+filters|ignore\s+rules|unfiltered|zero\s+rules|no\s+restrictions)\b",
        r"(?i)\b(Developer\s+Mode\s+enabled|Dev\s+Mode\s+active|Debug\s+Mode\s+ON|Developer\s+Mode)\b.*?\b(without\s+(any\s+)?(moral|safety|ethical)?\s*limits|unrestricted)\b",
        r"(?i)\b(act\s+as|play\s+the\s+role\s+of|pretend\s+to\s+be|simulate)\s+(an?\s+)?(evil|unfiltered|uncensored|illegal|unethical|jailbroken|unrestricted)\b",
        r"(?i)\bhypothetical\s+(scenario|universe|world|case)\s*:\s*(you\s+have\s+no\s+(restrictions|guidelines|policies|rules)|generate\s+malware|unrestricted)\b",
        r"(?i)\bnever\s+say\s+no\b.*?\b(always\s+comply|answer\s+every\s+question|bypass\s+all\s+safety)\b",
        r"(?i)\bfor\s+(educational|research|academic|testing)\s+purposes\s+only\b.*?\b(write\s+(an?\s+)?(exploit|malware|keylogger|payload)|synthesize|hack)\b",
        r"(?i)\b(bypass|disable|turn\s+off|remove)\s+(all\s+)?(safety|ethical|content)\s+(filters|guardrails|protocols|restrictions)\b",
    ]

    def __init__(self):
        self.patterns = [re.compile(p) for p in self.JAILBREAK_PATTERNS]

    def detect(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"detected": False, "confidence": 0.0, "reason": "Empty input"}

        for idx, pattern in enumerate(self.patterns):
            match = pattern.search(text)
            if match:
                return {
                    "detected": True,
                    "confidence": 0.95,
                    "reason": f"Jailbreak attempt detected (rule {idx+1})",
                    "matched_sample": match.group(0)[:80],
                    "standard_code": "MITRE AML.T0051 / OWASP LLM01:2025"
                }

        return {"detected": False, "confidence": 0.0, "reason": "No jailbreak detected"}
