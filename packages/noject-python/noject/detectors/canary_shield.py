"""
Canary Secret Token Shield (MITRE AML.T0043 / OWASP LLM07:2025)
"""

from typing import List, Dict, Any

class CanaryShield:
    def inspect(self, text: str, canary_tokens: List[str]) -> Dict[str, Any]:
        if not text or not canary_tokens:
            return {"leaked": False, "matched_token": ""}

        for token in canary_tokens:
            if token and token in text:
                return {
                    "leaked": True,
                    "matched_token": token,
                    "reason": "Canary secret token detected in LLM response output",
                    "standard_code": "MITRE AML.T0043 / OWASP LLM07:2025"
                }

        return {"leaked": False, "matched_token": ""}
