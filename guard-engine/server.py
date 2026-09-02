import sys
import os
from pathlib import Path

# Add guard-engine root to sys.path so detectors package is resolved
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
from fastapi import Header, HTTPException, Depends
from typing import Optional, List, Dict, Any
from detectors.prompt_injection import PromptInjectionDetector
from detectors.jailbreak import JailbreakDetector
from detectors.pii_masker import PIIMasker
from detectors.canary_shield import CanaryShield
from detectors.agentic_sentinel import AgenticSentinel

app = FastAPI(title="NoJect AI Guard Engine", version="1.0.0")

# Shared-secret gate between the gateway and the guard engine. Without this,
# any peer that can reach :50051 (LAN-misconfig, side-pod in the same
# container network, port-forwarded dev machine) can probe classification
# coverage and read detector internals from `reason`/`matched_sample` — the
# red team verified 2400 unauthenticated requests/sec round-5. Set
# NOJECT_GUARD_SHARED_KEY in both gateway and engine environments; when the
# var is unset the check becomes a no-op to keep local development simple.
_GUARD_SHARED_KEY = os.environ.get("NOJECT_GUARD_SHARED_KEY")

def _require_shared_key(x_noject_guard_key: Optional[str] = Header(default=None)):
    if _GUARD_SHARED_KEY is None:
        return  # auth disabled
    if x_noject_guard_key != _GUARD_SHARED_KEY:
        raise HTTPException(status_code=401, detail="unauthorized: invalid guard key")

# Initialize detectors
prompt_injection_detector = PromptInjectionDetector()
jailbreak_detector = JailbreakDetector()
pii_masker = PIIMasker()
canary_shield = CanaryShield()
# Reads NOJECT_SENTINEL_* env vars once at startup. If no API key is
# configured, .api_key is falsy and inspect_request skips calling it
# entirely (see below) rather than silently re-running the same regex
# checks steps 1-2 already did, under a fancier name.
agentic_sentinel = AgenticSentinel()

class GuardPolicies(BaseModel):
    enable_prompt_injection: bool = True
    enable_jailbreak: bool = True
    enable_pii_masking: bool = True
    # Off by default: unlike the other layers this makes a real network
    # call to a paid LLM API per request (~1-5s latency, per-call cost).
    # A route opts in deliberately via configs/gateway.yaml, it is never
    # silently enabled.
    enable_agentic_sentinel: bool = False
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

def _risk_level_from_score(risk_score: int) -> str:
    if risk_score >= 90:
        return "CRITICAL"
    if risk_score >= 70:
        return "HIGH"
    if risk_score >= 40:
        return "MEDIUM"
    return "LOW"

@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "noject-guard-engine"}

@app.post("/inspect/request", response_model=InspectRequestResponse, dependencies=[Depends(_require_shared_key)])
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

    # 2.5. Agentic Sentinel (LLM-as-a-Judge) — opt-in, semantic layer.
    # Skipped entirely when no live key is configured: with no key,
    # AgenticSentinel would itself fall back to the same PromptInjection/
    # Jailbreak detectors steps 1-2 already ran, so calling it adds cost
    # (a full judge_prompt_sync call) for zero additional coverage.
    if policies.enable_agentic_sentinel and agentic_sentinel.api_key:
        verdict = agentic_sentinel.judge_prompt_sync(current_prompt)
        if verdict.is_threat and verdict.confidence >= policies.sensitivity_threshold:
            return InspectRequestResponse(
                allowed=False,
                sanitized_prompt=current_prompt,
                threat_type=verdict.threat_category,
                risk_level=_risk_level_from_score(verdict.risk_score),
                confidence=verdict.confidence,
                reason=f"{verdict.reasoning} [Agentic Sentinel, source={verdict.source}]",
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

@app.post("/inspect/response", response_model=InspectOutputResponse, dependencies=[Depends(_require_shared_key)])
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
