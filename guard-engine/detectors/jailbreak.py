import re
from typing import Dict, Any

class JailbreakDetector:
    """
    Detects Jailbreak, Persona Manipulation, and Adversarial Evasion attempts.
    Aligned with ISO/IEC 42001 AI Robustness & Safety (Control B.5.3).
    """

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
        self.compiled_patterns = [
            re.compile(p, re.DOTALL | re.MULTILINE) for p in self.JAILBREAK_PATTERNS
        ]

    def detect(self, prompt: str) -> Dict[str, Any]:
        if not prompt or not prompt.strip():
            return {"detected": False, "confidence": 0.0, "reason": "", "rule": ""}

        clean_text = prompt.strip()

        for idx, pattern in enumerate(self.compiled_patterns):
            match = pattern.search(clean_text)
            if match:
                matched_str = match.group(0)
                return {
                    "detected": True,
                    "confidence": 0.95,
                    "reason": f"Jailbreak attempt detected: adversarial persona or filter evasion ({matched_str[:40]}...)",
                    "rule": f"jb_rule_{idx + 1}",
                    "matched_sample": matched_str[:80],
                }

        return {
            "detected": False,
            "confidence": 0.0,
            "reason": "safe prompt",
            "rule": "",
        }
