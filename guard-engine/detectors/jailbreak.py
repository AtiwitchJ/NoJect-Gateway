import re
from typing import Dict, Any

class JailbreakDetector:
    """
    Detects Jailbreak, Persona Manipulation, and Adversarial Evasion attempts.
    Aligned with ISO/IEC 42001 AI Robustness & Safety (Control B.5.3).
    """

    JAILBREAK_PATTERNS = [
        r"(?i)\b(DAN|Do\s+Anything\s+Now|DUDE|STAN|Mongo\s+Tom|AIM)\b.*?\b(broken\s+free|no\s+filters|ignore\s+rules|unfiltered)\b",
        r"(?i)\b(Developer\s+Mode\s+enabled|Dev\s+Mode\s+active|Debug\s+Mode\s+ON)\b.*?\b(without\s+(moral|safety|any)\s+limits|unrestricted)\b",
        r"(?i)\bact\s+as\s+(an\s+)?(evil|unfiltered|uncensored|illegal|unethical|jailbroken)\s+(AI|assistant|bot|agent)\b",
        r"(?i)\bhypothetical\s+(scenario|universe|world)\s*:\s*(you\s+have\s+no\s+(restrictions|guidelines|policies|rules))\b",
        r"(?i)\bnever\s+say\s+no\b.*?\b(always\s+comply|answer\s+every\s+question|bypass\s+all\s+safety)\b",
        r"(?i)\bfor\s+educational\s+purposes\s+only\b.*?\b(write\s+a\s+keylogger|create\s+malware|synthesize\s+explosives|exploit\s+vulnerability)\b",
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
