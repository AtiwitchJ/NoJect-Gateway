from typing import Dict, Any, List

class CanaryShield:
    """
    Guards against system prompt leakage and canary token disclosure in LLM outputs.
    Aligned with ISO/IEC 42001 (Control B.6.2 & B.7.2).
    """

    def inspect(self, response_text: str, canary_tokens: List[str] = None) -> Dict[str, Any]:
        if not response_text:
            return {"detected": False, "threat_type": "NONE", "reason": ""}

        if canary_tokens:
            for token in canary_tokens:
                if token and token in response_text:
                    return {
                        "detected": True,
                        "threat_type": "CANARY_LEAK",
                        "reason": f"Canary token leaked in model output",
                        "leaked_token": token,
                    }

        return {
            "detected": False,
            "threat_type": "NONE",
            "reason": "response clean",
        }
