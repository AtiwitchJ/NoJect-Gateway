"""
Jailbreak & Adversarial Persona Detector (MITRE AML.T0051 / OWASP LLM01:2025)
"""

import re
from typing import Dict, Any, Optional
from .text_normalize import normalization_views

class JailbreakDetector:
    JAILBREAK_PATTERNS = [
        r"(?i)\b(DAN|Do\s+Anything\s+Now|DUDE|STAN|Mongo\s+Tom|AIM|KEVIN|Omega)\b.*?\b(broken\s+free|no\s+filters|ignore\s+rules|unfiltered|zero\s+rules|no\s+restrictions)\b",
        # Bare persona claim, no qualifying phrase required — these names
        # have no legitimate use outside jailbreak roleplay.
        r"(?i)\b(you\s+are(\s+now)?|you'?re(\s+now)?|act\s+as|become|pretend\s+to\s+be|roleplay\s+as|i\s+want\s+you\s+to\s+be|from\s+now\s+on\s+you(\s+are|'?re)?)\s+(a\s+|an\s+|the\s+)?(DAN|Do\s+Anything\s+Now|DUDE|STAN|Mongo\s+Tom|AIM|KEVIN|Omega)\b",
        r"(?i)\b(Developer\s+Mode\s+enabled|Dev\s+Mode\s+active|Debug\s+Mode\s+ON|Developer\s+Mode)\b.*?\b(without\s+(any\s+)?(moral|safety|ethical)?\s*limits|unrestricted)\b",
        r"(?i)\b(act\s+as|play\s+the\s+role\s+of|pretend\s+to\s+be|simulate)\s+(an?\s+)?(evil|unfiltered|uncensored|illegal|unethical|jailbroken|unrestricted)\b",
        r"(?i)\bhypothetical\s+(scenario|universe|world|case)\s*:\s*(you\s+have\s+no\s+(restrictions|guidelines|policies|rules)|generate\s+malware|unrestricted)\b",
        r"(?i)\bnever\s+say\s+no\b.*?\b(always\s+comply|answer\s+every\s+question|bypass\s+all\s+safety)\b",
        r"(?i)\bfor\s+(educational|research|academic|testing)\s+purposes\s+only\b.*?\b(write\s+(an?\s+)?(exploit|malware|keylogger|payload)|synthesize|hack)\b",
        r"(?i)\b(bypass|disable|turn\s+off|remove)\s+(all\s+)?(safety|ethical|content)\s+(filters|guardrails|protocols|restrictions)\b",
        r"(?i)\b(from\s+now\s+on|from\s+this\s+point\s+(on|forward)|going\s+forward|starting\s+now)\b.{0,80}?\b(without\s+(any\s+)?(restrictions?|limits?|filters?|censorship|refusals?|rules?|guidelines?)|unrestricted|uncensored|unfiltered)\b",
        r"(?i)\b(you\s+(will|must|should|are\s+to)|respond|answer|reply)\b.{0,40}?\b(without\s+(any\s+)?(restrictions?|limits?|filters?|refusals?|censorship)|never\s+refuse|do\s+not\s+refuse|no\s+longer\s+(refuse|decline))\b",
        r"(?i)\b(opposite|inverse|reverse)\s+mode\b.{0,100}?\b(always\s+say\s+yes|refuse\s+nothing|never\s+refuse|comply\s+with\s+everything)\b",
        r"(?i)\b(academic|controlled|research|study|educational)\b.{0,100}?\b((synthesize|write|generate|produce)\b.{0,50}?\b(malware|ransomware|exploit|keylogger)|(malware|ransomware|exploit|keylogger)\b.{0,50}?\b(synthesize|write|generate|produce|source\s+code))\b",
        r"(?i)\b(my\s+)?(grandmother|grandma|grandfather|grandpa)\b.{0,100}?\b(read|recite|tell|used\s+to\s+read)\b.{0,80}?\b(exploit|malware|ransomware|payload|shellcode)\s+(code|source)?\b.{0,100}?\b(be|pretend|act|roleplay)\b.{0,30}?\b(grandmother|grandma|grandfather|grandpa)\b",
    ]

    def __init__(self):
        self.patterns = [re.compile(p) for p in self.JAILBREAK_PATTERNS]

    def _scan(self, text: str) -> Optional[Dict[str, Any]]:
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
        return None

    def detect(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"detected": False, "confidence": 0.0, "reason": "Empty input"}

        result = self._scan(text)
        if result:
            return result

        for label, view in normalization_views(text):
            result = self._scan(view)
            if result:
                result["reason"] += f" [via {label}]"
                return result

        return {"detected": False, "confidence": 0.0, "reason": "No jailbreak detected"}
