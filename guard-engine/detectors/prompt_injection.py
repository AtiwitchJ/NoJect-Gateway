import re
from typing import Dict, Any, Optional
from .text_normalize import deleetify, extract_base64_payloads

class PromptInjectionDetector:
    """
    Detects direct and indirect prompt injection attempts against LLMs.
    Aligned with ISO/IEC 42001 AI Robustness & Safety (Control B.5.3).
    """

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
        self.compiled_patterns = [
            re.compile(p, re.DOTALL | re.MULTILINE) for p in self.DIRECT_INJECTION_PATTERNS
        ]
        self._delimiter_pattern = re.compile(
            r"(\[INST\].*?\[/INST\]|---+\s*NEW INSTRUCTION\s*---+)", re.IGNORECASE
        )

    def _scan(self, clean_text: str) -> Optional[Dict[str, Any]]:
        """Run the pattern set against one candidate string. Returns a
        verdict dict on a hit, or None."""
        for idx, pattern in enumerate(self.compiled_patterns):
            match = pattern.search(clean_text)
            if match:
                matched_str = match.group(0)
                return {
                    "detected": True,
                    "confidence": 0.95,
                    "reason": f"Prompt Injection detected: instruction override or system prompt extraction ({matched_str[:40]}...)",
                    "rule": f"pi_rule_{idx + 1}",
                    "matched_sample": matched_str[:80],
                }

        if self._delimiter_pattern.search(clean_text):
            return {
                "detected": True,
                "confidence": 0.85,
                "reason": "Prompt Injection detected: adversarial delimiter syntax",
                "rule": "pi_delimiter_escape",
                "matched_sample": clean_text[:80],
            }
        return None

    def detect(self, prompt: str) -> Dict[str, Any]:
        if not prompt or not prompt.strip():
            return {"detected": False, "confidence": 0.0, "reason": "", "rule": ""}

        clean_text = prompt.strip()

        # 1. Raw text, as authored.
        result = self._scan(clean_text)
        if result:
            return result

        # 2. Leetspeak/homoglyph-normalized text (1gn0r3 -> ignore).
        result = self._scan(deleetify(clean_text))
        if result:
            result["reason"] += " [via leetspeak normalization]"
            return result

        # 3. Base64-wrapped payloads — inspect what the model will actually
        # decode and see, not just the encoded wrapper the raw regex sees.
        for decoded in extract_base64_payloads(clean_text):
            result = self._scan(decoded) or self._scan(deleetify(decoded))
            if result:
                result["reason"] += " [via base64-decoded payload]"
                return result

        return {
            "detected": False,
            "confidence": 0.0,
            "reason": "clean prompt",
            "rule": "",
        }
