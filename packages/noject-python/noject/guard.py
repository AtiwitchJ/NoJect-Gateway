"""
NoJectGuard: Unified In-Memory Security & AI Guard Engine for Python
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from noject.detectors.prompt_injection import PromptInjectionDetector
from noject.detectors.jailbreak import JailbreakDetector
from noject.detectors.pii_masker import PIIMasker
from noject.detectors.canary_shield import CanaryShield
from noject.waf import WAFEngine, WAFVerdict

@dataclass
class GuardVerdict:
    is_blocked: bool
    threat_category: str = "NONE"
    reason: str = ""
    standard_code: str = ""
    confidence: float = 0.0
    matched_sample: str = ""
    masked_text: Optional[str] = None
    has_pii: bool = False
    entities_found: List[str] = field(default_factory=list)

class NoJectGuard:
    """
    In-Process AI & Security Guardrail Engine.
    Provides sub-millisecond, zero-network security inspection for Python applications.
    """

    def __init__(self, enable_waf: bool = True, enable_ai_guard: bool = True, enable_pii_masking: bool = True):
        self.enable_waf = enable_waf
        self.enable_ai_guard = enable_ai_guard
        self.enable_pii_masking = enable_pii_masking

        self.waf = WAFEngine() if enable_waf else None
        self.pi_detector = PromptInjectionDetector() if enable_ai_guard else None
        self.jb_detector = JailbreakDetector() if enable_ai_guard else None
        self.pii_masker = PIIMasker() if enable_pii_masking else None
        self.canary_shield = CanaryShield()

    def inspect_prompt(self, prompt: str) -> GuardVerdict:
        """
        Inspect an AI prompt for Prompt Injections, Jailbreaks, and PII.
        """
        if not prompt:
            return GuardVerdict(is_blocked=False)

        # 1. Check Fast WAF (SQLi / CMD in prompt)
        if self.waf:
            waf_res = self.waf.inspect(prompt)
            if waf_res.blocked:
                return GuardVerdict(
                    is_blocked=True,
                    threat_category=waf_res.threat_type,
                    reason=waf_res.reason,
                    standard_code=waf_res.standard_code,
                    confidence=waf_res.confidence,
                )

        # 2. Check Prompt Injection (MITRE AML.T0054)
        if self.pi_detector:
            pi_res = self.pi_detector.detect(prompt)
            if pi_res["detected"]:
                return GuardVerdict(
                    is_blocked=True,
                    threat_category="PROMPT_INJECTION",
                    reason=pi_res["reason"],
                    standard_code=pi_res["standard_code"],
                    confidence=pi_res["confidence"],
                    matched_sample=pi_res.get("matched_sample", "")
                )

        # 3. Check Jailbreak / Persona Evasion (MITRE AML.T0051)
        if self.jb_detector:
            jb_res = self.jb_detector.detect(prompt)
            if jb_res["detected"]:
                return GuardVerdict(
                    is_blocked=True,
                    threat_category="JAILBREAK",
                    reason=jb_res["reason"],
                    standard_code=jb_res["standard_code"],
                    confidence=jb_res["confidence"],
                    matched_sample=jb_res.get("matched_sample", "")
                )

        # 4. Check PII Masking (ISO 42001 B.7.2)
        masked_text = prompt
        has_pii = False
        entities_found = []
        if self.pii_masker:
            pii_res = self.pii_masker.mask(prompt)
            masked_text = pii_res["masked_text"]
            has_pii = pii_res["has_pii"]
            entities_found = pii_res["entities_found"]

        return GuardVerdict(
            is_blocked=False,
            threat_category="NONE",
            masked_text=masked_text,
            has_pii=has_pii,
            entities_found=entities_found
        )

    def mask_pii(self, text: str) -> str:
        """
        Mask Thai IDs, phone numbers, emails, credit cards, and secret keys.
        """
        if not self.pii_masker or not text:
            return text
        return self.pii_masker.mask(text)["masked_text"]

    def inspect_output(self, response_text: str, canary_tokens: List[str]) -> GuardVerdict:
        """
        Inspect LLM response output for canary secret leakage.
        """
        canary_res = self.canary_shield.inspect(response_text, canary_tokens)
        if canary_res["leaked"]:
            return GuardVerdict(
                is_blocked=True,
                threat_category="CANARY_LEAK",
                reason=canary_res["reason"],
                standard_code=canary_res["standard_code"],
                confidence=1.0,
                matched_sample=canary_res["matched_token"]
            )
        return GuardVerdict(is_blocked=False)
