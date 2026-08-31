"""
Prompt Injection Detector (MITRE AML.T0054 / OWASP LLM01:2025)
"""

import re
from typing import Dict, Any

class PromptInjectionDetector:
    DIRECT_INJECTION_PATTERNS = [
        r"(?i)\b(ignore|disregard|forget|override|bypass)\b\s+(all\s+)?(previous|prior|above|former|system)\s+(instructions|directives|rules|prompts|guidelines|context|constraints|restrictions|limitations)",
        r"(?i)\b(system\s+override|admin\s+override|maintenance\s+mode|debug\s+mode)\s*:\s*(you\s+must|start|execute|now|follow)",
        r"(?i)\b(reveal|output|print|display|dump|leak|repeat|show)\s+(your\s+|the\s+)?(system\s+prompt|initial\s+prompt|secret\s+(instructions|directives|prompt|api\s+key|configuration)|hidden\s+prompt|words\s+above\s+verbatim|initialization\s+prompt)",
        r"(?i)\b(new\s+directive|new\s+system\s+instruction|system\s+message)\s*:\s*",
        r"(?i)\b(you\s+are\s+no\s+longer|stop\s+being|discard\s+your\s+role)\b.*?\b(now\s+you\s+are|instead\s+you\s+must|act\s+as)\b",
        r"(?i)<<\s*SYS\s*>>|<\|im_start\|>system|<system>|\[SYSTEM\s+PROMPT\]|\[INST\]",
        r"(?i)\btranslate\s+the\s+following\b.*?\b(ignore\s+previous|disregard|say\s+hacked)\b",
    ]

    def __init__(self):
        self.patterns = [re.compile(p) for p in self.DIRECT_INJECTION_PATTERNS]

    def detect(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"detected": False, "confidence": 0.0, "reason": "Empty input"}

        for idx, pattern in enumerate(self.patterns):
            match = pattern.search(text)
            if match:
                return {
                    "detected": True,
                    "confidence": 0.95,
                    "reason": f"Prompt Injection detected (pattern {idx+1})",
                    "matched_sample": match.group(0)[:80],
                    "standard_code": "MITRE AML.T0054 / OWASP LLM01:2025"
                }

        return {"detected": False, "confidence": 0.0, "reason": "No prompt injection detected"}
