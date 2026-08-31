# NoJect: Universal AI & Security API Gateway
## Technical Design Specification

- **Date:** 2026-08-31
- **Status:** Approved for Implementation
- **Target Audience:** Open Source Community, Enterprise SecOps, AI Engineers
- **Compliance Baseline:** ISO/IEC 27001 (ISMS), ISO/IEC 42001 (AIMS), ISO/IEC 27034 (Application Security)

---

## 1. Executive Summary

**NoJect** is an open-source, high-performance, ISO-compliant Universal Security and AI API Gateway. It sits as a reverse proxy in front of AI/LLM providers (e.g., OpenAI, Anthropic, Ollama, vLLM) and backend REST APIs to provide unified authentication, fast-path threat mitigation (SQLi, XSS, Command Injection), context-aware AI guardrails (Prompt Injection, Jailbreak, System Prompt Leakage, PII redaction), and tamper-evident audit logging.

### Key Objectives
1. **Multi-Vector Threat Defense**: Protect against both traditional web injection attacks (OWASP Top 10) and LLM-specific threats (OWASP Top 10 for LLM).
2. **Dual-Engine High Performance**: Combine Go for microsecond-latency reverse proxying, authentication, and rule-based WAF with Python for AI safety detection and NLP processing.
3. **Pluggable Multi-Auth**: Support API Keys, JWT/OIDC, and HMAC signatures out of the box.
4. **ISO-Compliant by Design**: Incorporate structured, tamper-evident (cryptographic hash-chained) audit logs and access controls aligned with ISO/IEC 27001 and ISO/IEC 42001.

---

## 2. ISO Standards Compliance Matrix

| Standard | Clause / Control | Requirement | NoJect Gateway Implementation |
| :--- | :--- | :--- | :--- |
| **ISO/IEC 27001:2022** | **A.8.2** Privileged Access | Enforce least privilege and strict access control | RBAC per API Key and JWT role/scope verification with fine-grained route permissions. |
| **ISO/IEC 27001:2022** | **A.8.15** Logging | Tamper-evident logging of security events and access | Immutable, structured JSON audit trail with SHA-256 cryptographic hash-chaining and W3C trace IDs. |
| **ISO/IEC 27001:2022** | **A.8.24** Cryptography | Secure data in transit and rest | Mandatory TLS 1.3 support, secure key hashing (Argon2/SHA-256), and safe memory clearing for secrets. |
| **ISO/IEC 27001:2022** | **A.8.28** Secure Coding & Input Validation | Prevent injection and malformed inputs | Fast-path WAF inspecting query params, headers, and request body for SQLi, XSS, Path Traversal, and Command Injection. |
| **ISO/IEC 42001:2023** | **B.5.3** AI Robustness & Safety | Protect AI against adversarial inputs | Multi-tier prompt injection and jailbreak classifier pipeline (rule-based + heuristic + transformer models). |
| **ISO/IEC 42001:2023** | **B.6.2** AI Transparency | Explainable guardrail decisions | Every blocked/flagged request contains reason codes, category taxonomy, and risk confidence scores. |
| **ISO/IEC 42001:2023** | **B.7.2** AI Data Privacy | Prevent leakage of personal data | Automated PII masking/anonymization engine before forwarding payloads to external LLM providers. |
| **ISO/IEC 27034** | **ASC Controls** | Standardized Application Security Controls | Clear separation of Gateway boundary, Guardrail layer, and Upstream targets. |

---

## 3. High-Level Architecture

```
[ Client / Application ]
         │
         ▼ (HTTPS / TLS 1.3)
┌─────────────────────────────────────────────────────────────┐
│  Go Gateway (L7 Reverse Proxy & Fast Shield)                │
│  - Multi-Auth Engine (API Key, JWT/OIDC, HMAC)              │
│  - Rate Limiter (Token Bucket / Redis)                      │
│  - Fast WAF (SQLi, XSS, CMD Injection, Path Traversal)      │
│  - Route Matcher & Upstream Forwarder                       │
└──────────────┬──────────────────────────────┬───────────────┘
               │ (Internal gRPC/UDS)          │ (Fast Path / No AI)
               ▼                              │
┌──────────────────────────────┐              │
│ Python AI Guard Engine       │              │
│ - Prompt Injection Detector  │              │
│ - Jailbreak Classifier       │              │
│ - PII Anonymizer / Masker    │              │
│ - System Prompt Leak Shield  │              │
└──────────────┬───────────────┘              │
               │ (Verdict: Allow/Block/Mask)  │
               └──────────────┬───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Upstream Targets                                           │
│  - Option A: LLM Provider (OpenAI, Anthropic, Ollama, vLLM) │
│  - Option B: Upstream REST / GraphQL Backend API            │
└─────────────────────────────┬───────────────────────────────┘
                              │ (Response Body)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Response Guardrail & ISO Audit Logger                      │
│  - Canary Token & Secret Leakage Inspection                 │
│  - Tamper-Evident Hash-Chained Audit Trail (JSON)           │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Subsystem Specifications

### 4.1. Go Gateway Core (`cmd/gateway`, `internal/`)
- **Transport**: High-throughput HTTP/1.1 and HTTP/2 reverse proxy using Go standard library and fasthttp/net/http with connection pooling.
- **Authentication Subsystem (`internal/auth`)**:
  - **API Key**: Extracted from `X-API-Key` or `Authorization: Bearer <key>`. Stored with Argon2id / SHA-256 hashes in local memory or Redis.
  - **JWT / OIDC**: Validates asymmetric signatures (RS256, ES256, EdDSA) via remote or cached JWKS. Validates `exp`, `nbf`, `iss`, `aud`, and evaluates role/scope constraints.
  - **HMAC**: Validates `X-Signature-SHA256` headers for service-to-service communication.
- **Fast-Path WAF Subsystem (`internal/waf`)**:
  - Pre-compiled regular expressions and tokenizers targeting SQLi keywords (`UNION`, `SELECT`, `OR 1=1`), XSS vectors (`<script>`, `onerror=`, `javascript:`), and OS command injection tokens (`;`, `&&`, `|`, `$(...)`, `../`).
  - Executed synchronously on headers, query strings, and body with sub-millisecond execution budget.
- **Upstream Router (`internal/router`)**:
  - Matches paths using prefix or wildcard matching (e.g., `/v1/chat/completions`, `/api/*`).
  - Configures per-route guardrail flags (e.g. enable AI guard for LLM routes, enable SQLi/XSS for REST routes).

### 4.2. Python AI Guard Engine (`guard-engine/`)
- **Communication**: Low-latency gRPC service over Unix Domain Socket (UDS) or internal TCP.
- **Inspection Modules**:
  1. **Prompt Injection Classifier**: Hybrid detection combining heuristic signatures, semantic embedding distance, and ONNX/Transformer classification models (e.g., lightweight DeBERTa / protect-ai models).
  2. **Jailbreak & Adversarial Detector**: Recognizes DAN patterns, developer mode overrides, and adversarial suffix attacks.
  3. **PII Anonymizer**: Detects phone numbers, emails, national ID numbers (Thai ID, SSN), credit cards, and API keys. Provides configurable actions: `MASK`, `REDACT`, or `BLOCK`.
  4. **System Prompt Protection**: Checks for attempts to leak system instructions (e.g. "repeat the text above verbatim").
- **Output Inspection**: Scans upstream LLM response for Canary Tokens and accidental disclosure of internal system prompts or secrets.

### 4.3. Audit & Logging Subsystem (`internal/audit`)
- **Format**: JSON Lines conforming to ECS (Elastic Common Schema) and ISO/IEC 27001 logging criteria.
- **Schema Fields**:
  - `timestamp`: ISO-8601 UTC with microsecond precision.
  - `trace_id`: W3C traceparent identifier.
  - `client_id` / `api_key_id`: Subject identifier.
  - `client_ip`: Remote IP (respecting trusted proxy headers).
  - `route`: Matched route pattern.
  - `action`: `ALLOWED`, `BLOCKED`, `MASKED`.
  - `threat_category`: `NONE`, `SQL_INJECTION`, `XSS`, `PROMPT_INJECTION`, `JAILBREAK`, `PII_DETECTED`.
  - `severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
  - `confidence`: Confidence score (0.0 - 1.0) from AI guardrail.
  - `prev_record_hash`: SHA-256 hash of the preceding log entry.
  - `record_hash`: SHA-256 hash of the current log entry combined with `prev_record_hash`.

---

## 5. Data Contracts & Interfaces

### 5.1. Protobuf Interface (`proto/guard.proto`)
```protobuf
syntax = "proto3";

package guard;
option go_package = "noject/proto/guard";

service GuardService {
  rpc InspectRequest (InspectReq) returns (InspectResp);
  rpc InspectResponse (InspectOutputReq) returns (InspectOutputResp);
}

message InspectReq {
  string trace_id = 1;
  string route = 2;
  string prompt = 3;
  map<string, string> metadata = 4;
  GuardPolicies policies = 5;
}

message GuardPolicies {
  bool enable_prompt_injection = 1;
  bool enable_jailbreak = 2;
  bool enable_pii_masking = 3;
  double sensitivity_threshold = 4;
}

message InspectResp {
  bool allowed = 1;
  string sanitized_prompt = 2;
  string threat_type = 3;
  string risk_level = 4;
  double confidence = 5;
  string reason = 6;
}

message InspectOutputReq {
  string trace_id = 1;
  string response_text = 2;
  repeated string canary_tokens = 3;
}

message InspectOutputResp {
  bool allowed = 1;
  string sanitized_response = 2;
  string threat_type = 3;
  string reason = 4;
}
```

### 5.2. Declarative Configuration Schema (`configs/gateway.yaml`)
```yaml
version: "1.0"
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: ""
    key_file: ""

auth:
  api_key:
    enabled: true
    header: "X-API-Key"
  jwt:
    enabled: true
    jwks_url: "https://auth.example.com/.well-known/jwks.json"
    issuer: "https://auth.example.com"
    audience: "noject-gateway"

guard_engine:
  endpoint: "localhost:50051"
  timeout_ms: 1500
  fallback_action: "BLOCK" # "BLOCK" or "ALLOW" on guard failure

routes:
  - id: "openai-proxy"
    path: "/v1/chat/completions"
    upstream: "https://api.openai.com/v1/chat/completions"
    type: "llm"
    auth_required: true
    guardrails:
      fast_waf: false
      prompt_injection: true
      jailbreak: true
      pii_masking: true
      output_guard: true

  - id: "backend-api"
    path: "/api/*"
    upstream: "http://backend-service:3000"
    type: "rest"
    auth_required: true
    guardrails:
      fast_waf: true
      prompt_injection: false
      jailbreak: false
      pii_masking: false
      output_guard: false

audit:
  driver: "file"
  output_path: "logs/audit.log"
  hash_chaining: true
  iso_compliance_mode: true
```

---

## 6. Project Repository Layout

```
NoJect/
├── cmd/
│   └── gateway/             # Go Gateway Main Entrypoint (main.go)
├── internal/
│   ├── auth/                # Multi-Auth Handlers (API Key, JWT, HMAC)
│   ├── waf/                 # Fast-Path WAF Rules (SQLi, XSS, CMD)
│   ├── router/              # Reverse Proxy & Upstream Router
│   ├── guardclient/         # gRPC Client to Python Guard
│   ├── audit/               # ISO 27001 Hash-Chained Audit Trail
│   └── config/              # YAML Configuration Loader & Validator
├── proto/
│   └── guard.proto          # gRPC Definition
├── guard-engine/            # Python AI Guard Engine
│   ├── server.py            # gRPC Server
│   ├── detectors/
│   │   ├── prompt_injection.py
│   │   ├── jailbreak.py
│   │   ├── pii_masker.py
│   │   └── canary_shield.py
│   ├── models/              # Local ML / Heuristic Rule Sets
│   ├── requirements.txt
│   └── Dockerfile.guard
├── configs/
│   ├── gateway.yaml         # Sample Gateway Config
│   └── api_keys.yaml        # Local API Key DB (for dev/standalone)
├── deployments/
│   ├── docker-compose.yml   # 1-Click Launch
│   └── Dockerfile.gateway
├── docs/
│   ├── ISO_COMPLIANCE.md    # Mapping to ISO 27001, 42001, 27034
│   └── QUICKSTART.md
├── Makefile                 # Build, Proto Gen, Test, Run
├── go.mod
└── go.sum
```

---

## 7. Verification & Testing Strategy

1. **Unit Testing**:
   - Go: Comprehensive tests for Auth validators, WAF pattern matching, and Audit Hash chaining.
   - Python: Unit tests for Prompt Injection payloads, Jailbreak permutations, and PII masking accuracy.
2. **Integration Testing**:
   - End-to-end proxy tests: Sending valid and malicious requests to the Go Gateway and asserting proper `403 Forbidden` / `200 OK` status codes and audit log entries.
3. **ISO Compliance Audit Verification**:
   - Script to verify that generated audit logs maintain valid SHA-256 hash chaining with zero broken links.
4. **Performance Benchmark**:
   - Benchmark throughput and latency overhead of the Go Fast-path (< 2ms) and Python AI Guard (< 100ms for lightweight local models).

---

## 8. Open Source & Community Readiness

- Fully containerized with `docker-compose.yml`.
- Standard MIT / Apache 2.0 open-source licensing.
- Clear documentation for configuring downstream LLM APIs (OpenAI, Claude, Ollama) and custom REST APIs.
