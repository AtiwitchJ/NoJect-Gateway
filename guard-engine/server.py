import sys
from pathlib import Path

# Add guard-engine root to sys.path so detectors package is resolved
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from detectors.prompt_injection import PromptInjectionDetector
from detectors.jailbreak import JailbreakDetector
from detectors.pii_masker import PIIMasker
from detectors.canary_shield import CanaryShield

app = FastAPI(title="NoJect AI Guard Engine", version="1.0.0")

# Initialize detectors
prompt_injection_detector = PromptInjectionDetector()
jailbreak_detector = JailbreakDetector()
pii_masker = PIIMasker()
canary_shield = CanaryShield()

class GuardPolicies(BaseModel):
    enable_prompt_injection: bool = True
    enable_jailbreak: bool = True
    enable_pii_masking: bool = True
    sensitivity_threshold: float = 0.7

class InspectRequestPayload(BaseModel):
    trace_id: str = Field(..., description="W3C traceparent identifier")
    route: str = Field(default="")
    prompt: str = Field(..., description="The user prompt or query to inspect")
    metadata: Optional[Dict[str, str]] = None
    policies: Optional[GuardPolicies] = None

class InspectRequestResponse(BaseModel):
    allowed: bool
    sanitized_prompt: str
    threat_type: str
    risk_level: str
    confidence: float
    reason: str

class InspectOutputPayload(BaseModel):
    trace_id: str
    response_text: str
    canary_tokens: Optional[List[str]] = None

class InspectOutputResponse(BaseModel):
    allowed: bool
    sanitized_response: str
    threat_type: str
    reason: str

@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "noject-guard-engine"}

@app.post("/inspect/request", response_model=InspectRequestResponse)
def inspect_request(payload: InspectRequestPayload):
    policies = payload.policies or GuardPolicies()
    current_prompt = payload.prompt

    # 1. Inspect for Prompt Injection
    if policies.enable_prompt_injection:
        pi_res = prompt_injection_detector.detect(current_prompt)
        if pi_res["detected"] and pi_res["confidence"] >= policies.sensitivity_threshold:
            return InspectRequestResponse(
                allowed=False,
                sanitized_prompt=current_prompt,
                threat_type="PROMPT_INJECTION",
                risk_level="CRITICAL",
                confidence=pi_res["confidence"],
                reason=pi_res["reason"],
            )

    # 2. Inspect for Jailbreak
    if policies.enable_jailbreak:
        jb_res = jailbreak_detector.detect(current_prompt)
        if jb_res["detected"] and jb_res["confidence"] >= policies.sensitivity_threshold:
            return InspectRequestResponse(
                allowed=False,
                sanitized_prompt=current_prompt,
                threat_type="JAILBREAK",
                risk_level="HIGH",
                confidence=jb_res["confidence"],
                reason=jb_res["reason"],
            )

    # 3. PII Masking
    threat_type = "NONE"
    risk_level = "LOW"
    confidence = 0.0
    reason = "request passed guardrails"

    if policies.enable_pii_masking:
        pii_res = pii_masker.mask(current_prompt)
        if pii_res["has_pii"]:
            current_prompt = pii_res["sanitized_text"]
            threat_type = "PII_DETECTED"
            risk_level = "MEDIUM"
            confidence = 0.9
            reason = f"Masked sensitive PII entities: {[e['type'] for e in pii_res['detected_entities']]}"

    return InspectRequestResponse(
        allowed=True,
        sanitized_prompt=current_prompt,
        threat_type=threat_type,
        risk_level=risk_level,
        confidence=confidence,
        reason=reason,
    )

@app.post("/inspect/response", response_model=InspectOutputResponse)
def inspect_response(payload: InspectOutputPayload):
    res = canary_shield.inspect(payload.response_text, payload.canary_tokens)
    if res["detected"]:
        return InspectOutputResponse(
            allowed=False,
            sanitized_response="[BLOCKED: Internal Canary Secret Leaked]",
            threat_type=res["threat_type"],
            reason=res["reason"],
        )

    return InspectOutputResponse(
        allowed=True,
        sanitized_response=payload.response_text,
        threat_type="NONE",
        reason="response clean",
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=50051)
