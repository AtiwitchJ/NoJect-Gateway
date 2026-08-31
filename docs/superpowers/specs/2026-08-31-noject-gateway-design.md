# NoJect: Universal AI & Security API Gateway
## Technical Design Specification

- **Date:** 2026-08-31
- **Status:** Draft — Phase 1 (MVP) scoped for implementation; later phases indicative
- **Target Audience:** Open Source Community, Enterprise SecOps, AI Engineers
- **Standards Alignment:** Designed to *support* controls from ISO/IEC 27001 (ISMS), ISO/IEC 42001 (AIMS), and ISO/IEC 27034 (Application Security)

---

## 1. Executive Summary

**NoJect** is an open-source, high-performance Universal Security and AI API Gateway, built to support ISO-aligned security and AI-governance controls. It sits as a reverse proxy in front of AI/LLM providers (e.g., OpenAI, Anthropic, Ollama, vLLM) and backend REST APIs to provide unified authentication, fast-path threat mitigation (SQLi, XSS, Command Injection), context-aware AI guardrails (Prompt Injection, Jailbreak, System Prompt Leakage, PII redaction), and tamper-evident audit logging.

### Key Objectives
1. **Multi-Vector Threat Defense**: Protect against both traditional web injection attacks (OWASP Top 10) and LLM-specific threats (OWASP Top 10 for LLM).
2. **Performance-Tiered Design**: Go carries the microsecond-latency fast path — reverse proxying, authentication, rule-based WAF. AI safety detection runs in-process as heuristics in the MVP and splits into a separate Python engine only when model-based detection earns the second runtime (see §7).
3. **Pluggable Multi-Auth**: Support API Keys, JWT/OIDC, and HMAC signatures out of the box.
4. **Evidence for ISO-Aligned Controls**: Produce structured, tamper-evident (cryptographic hash-chained) audit logs and enforce access controls that map onto ISO/IEC 27001 and ISO/IEC 42001 requirements. Certification is an organization-level outcome covering an entire management system; a gateway supplies evidence and enforcement for specific controls, it does not confer compliance.

---

## 2. ISO Standards Control-Support Matrix

This maps gateway features onto controls an organization must satisfy. It is a statement of what NoJect helps enforce and evidence — not a claim that deploying it makes anyone certified. Rows marked *(Phase 2/3)* describe target-state capability, not the MVP (§7).

| Standard | Clause / Control | Requirement | NoJect Gateway Implementation |
| :--- | :--- | :--- | :--- |
| **ISO/IEC 27001:2022** | **A.8.2** Privileged Access | Enforce least privilege and strict access control | Per-API-key route permissions in the MVP; JWT role/scope verification and finer-grained RBAC *(Phase 3)*. |
| **ISO/IEC 27001:2022** | **A.8.15** Logging | Tamper-evident logging of security events and access | Immutable, structured JSON audit trail with SHA-256 cryptographic hash-chaining and W3C trace IDs. |
| **ISO/IEC 27001:2022** | **A.8.24** Cryptography | Secure data in transit and rest | TLS 1.3 support (recommended; opt-in for local dev, enforced in production configs). API keys are high-entropy random tokens hashed with SHA-256 (constant-time compare); Argon2id is reserved for user passwords only. Safe memory clearing for secrets. |
| **ISO/IEC 27001:2022** | **A.8.28** Secure Coding & Input Validation | Prevent injection and malformed inputs | Fast-path WAF inspecting query params, headers, and request body for SQLi, XSS, Path Traversal, and Command Injection. |
| **ISO/IEC 42001:2023** | **B.5.3** AI Robustness & Safety | Protect AI against adversarial inputs | Heuristic and signature-based prompt-injection and jailbreak detection in the MVP; transformer/embedding classifier tiers *(Phase 2)*. |
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
- **Transport**: High-throughput HTTP/1.1 and HTTP/2 reverse proxy built on Go's standard library (`net/http` + `httputil.ReverseProxy`) with connection pooling. `net/http` is chosen deliberately over `fasthttp`: the standard proxy supports response streaming (SSE), which LLM upstreams require, and `fasthttp`'s incompatible handler model would break it.
- **Authentication Subsystem (`internal/auth`)**:
  - **API Key**: Extracted from `X-API-Key` or `Authorization: Bearer <key>`. Keys are high-entropy random tokens, so they are stored and verified with a plain **SHA-256** hash and constant-time comparison — *not* Argon2. Argon2id is a deliberately slow KDF (~100ms) meant for low-entropy human passwords; running it per request would blow the sub-2ms fast-path budget. Hashes live in local memory or Redis.
  - **JWT / OIDC**: Validates asymmetric signatures (RS256, ES256, EdDSA) via remote or cached JWKS. Validates `exp`, `nbf`, `iss`, `aud`, and evaluates role/scope constraints.
  - **HMAC**: Validates `X-Signature-SHA256` headers for service-to-service communication.
- **Rate Limiter (`internal/ratelimit`)**: Token bucket keyed by API key identity, falling back to client IP for unauthenticated routes. In-process buckets for the single-instance MVP; Redis-backed shared buckets when running multiple instances (Phase 3). Limits are set globally and overridable per route.
- **Fast-Path WAF Subsystem (`internal/waf`)**:
  - Pre-compiled regular expressions and tokenizers targeting SQLi keywords (`UNION`, `SELECT`, `OR 1=1`), XSS vectors (`<script>`, `onerror=`, `javascript:`), and OS command injection tokens.
  - **Inspection scope is deliberately narrow, because shell metacharacters are ordinary text.** Tokens like `;`, `&&`, `|`, and `../` occur constantly in legitimate JSON bodies — prose, markdown, file paths, regexes — so matching them raw against a request body produces a false-positive storm that blocks real traffic. Therefore:
    - Command-injection and path-traversal rules run on **URL path, query string, and headers only** — the places those tokens have no innocent reason to appear.
    - Body inspection is limited to SQLi and XSS signatures, applied to **decoded string values** of parsed JSON/form fields rather than the raw byte stream, so structural punctuation is never mistaken for an attack.
    - Every rule carries a severity and can be individually disabled per route; a route that legitimately carries shell-like content can turn off the offending rule instead of the whole WAF.
  - **Bounded work per request.** Body inspection reads at most `max_inspect_bytes` (default 1 MiB). An unbounded synchronous scan is a denial-of-service vector: a single multi-gigabyte body would otherwise be read into memory and regex-scanned while holding a worker. On exceeding the cap the configured `oversize_action` applies — `BLOCK` (default, fail-closed) or `SKIP` (forward uninspected and record the omission in the audit log). Requests exceeding `max_body_bytes` are rejected outright with `413`.
  - Executed synchronously on headers, query strings, and bounded body with sub-millisecond execution budget.
- **Upstream Router (`internal/router`)**:
  - Matches paths using prefix or wildcard matching (e.g., `/v1/chat/completions`, `/api/*`).
  - Configures per-route guardrail flags (e.g. enable AI guard for LLM routes, enable SQLi/XSS for REST routes).

### 4.2. Python AI Guard Engine (`guard-engine/`)
- **Communication**: Low-latency gRPC service over Unix Domain Socket (UDS) or internal TCP.
- **Inspection Modules**:
  1. **Prompt Injection Classifier**: Hybrid detection combining heuristic signatures, semantic embedding distance, and ONNX/Transformer classification models (e.g., lightweight DeBERTa / protect-ai models).
  2. **Jailbreak & Adversarial Detector**: Recognizes DAN patterns, developer mode overrides, and adversarial suffix attacks.
  3. **PII Anonymizer (reversible)**: Detects phone numbers, emails, national ID numbers (Thai ID, SSN), credit cards, and API keys. Configurable actions: `MASK`, `REDACT`, or `BLOCK`.
     - **Masking must be reversible, or the gateway breaks the feature it proxies.** If a phone number is replaced with `<PHONE_1>` on the way out, the model's answer comes back containing `<PHONE_1>`, and a client that asked "what is this customer's number?" receives a placeholder. So `MASK` writes a per-request **placeholder → original** map, keyed by `trace_id`, held in memory (or Redis) with a short TTL bounded by the request lifetime, and the response guard substitutes the originals back before the body reaches the client. In streaming mode the substitution runs on the same sliding window as canary scanning, since a placeholder can straddle a chunk boundary.
     - The map is secret material: never logged, never written to the audit trail (audit records the *fact* of masking and the entity types, not the values), and cleared on request completion or TTL expiry.
     - `REDACT` and `BLOCK` are one-way by definition and need no map.
  4. **System Prompt Protection**: Checks for attempts to leak system instructions (e.g. "repeat the text above verbatim").
- **Output Inspection (streaming-aware)**: LLM upstreams stream responses as Server-Sent Events, so the response guard **must not** buffer the whole body before the client sees anything — that would destroy time-to-first-token. Design:
  - **Pass-through by default with a sliding-window scanner.** The gateway relays chunks to the client while a bounded rolling buffer (e.g. last N KB, spanning chunk boundaries) is scanned for canary tokens, known secret patterns, and system-prompt-leak signatures.
  - **Block-on-detect.** On a hit, the stream is cut immediately (connection closed / error frame), so partial leaked bytes may already be in flight — this is an accepted, documented limitation of streaming inspection. Routes needing hard guarantees can set `output_guard_mode: buffered` to hold the full response before release, trading TTFT for certainty.
  - **Canary tokens** are injected into the system prompt out-of-band and matched against outgoing chunks; a match means the model was induced to reveal instructions.

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
- **Chain Rules** (a hash chain is only tamper-evident if these are pinned down):
  - **Genesis**: the first record of a chain sets `prev_record_hash` to 64 zero characters. A chain-start marker record carries the gateway instance ID and boot timestamp so verification has a defined origin.
  - **Canonicalization**: `record_hash = SHA-256(prev_record_hash || canonical_json(record_without_record_hash))`, where canonical JSON means sorted keys and no insignificant whitespace. Without a fixed serialization, an independent verifier cannot reproduce the hash.
  - **Rotation continuity**: on rotation, the first record of the new file repeats the last `record_hash` of the previous file as its `prev_record_hash`, and names the predecessor file. The chain therefore spans files, and the verification script (§8) walks rotated files in order rather than treating each as an independent chain.
  - **Durability**: records are appended and `fsync`ed before the gateway returns its response for `BLOCKED` decisions; a crash must not lose the record of a security event. High-volume `ALLOWED` records may batch-sync on a configurable interval, accepting the loss of the trailing batch — the chain stays valid because the truncation is at the tail, which verification reports as a short chain rather than a broken one.
  - **Single writer**: one process, one chain. Appends serialize through a single writer, which is the reason this design is single-node until Phase 3 addresses horizontal scale.

---

## 5. Data Contracts & Interfaces

### 5.1. Protobuf Interface (`proto/guard.proto`)
```protobuf
syntax = "proto3";

package guard;
option go_package = "noject/proto/guard";

service GuardService {
  rpc InspectRequest (InspectReq) returns (InspectResp);

  // Response inspection is bidirectionally streamed: the gateway forwards each
  // upstream chunk as it arrives and receives a verdict per chunk, so nothing
  // has to buffer the full body (see §4.2 Output Inspection). A unary call
  // here would force full buffering and destroy time-to-first-token.
  rpc InspectResponse (stream InspectOutputReq) returns (stream InspectOutputResp);
}

// A single turn in an LLM conversation. LLM requests are message arrays,
// not one flat string — flattening loses the role structure that both
// injection detection and faithful request reconstruction depend on.
message ChatMessage {
  string role = 1;     // "system" | "user" | "assistant" | "tool"
  string content = 2;
}

message InspectReq {
  string trace_id = 1;
  string route = 2;
  repeated ChatMessage messages = 3;   // full conversation, structure preserved
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
  repeated ChatMessage sanitized_messages = 2;  // masked/rewritten, structure intact
  string threat_type = 3;
  string risk_level = 4;
  double confidence = 5;
  string reason = 6;
}

message InspectOutputReq {
  string trace_id = 1;
  string chunk = 2;                  // one upstream chunk, not the whole body
  repeated string canary_tokens = 3; // sent on the first message of the stream
  bool is_final = 4;                 // upstream stream finished
}

message InspectOutputResp {
  bool allowed = 1;          // false = cut the stream immediately
  string sanitized_chunk = 2;
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
    enabled: false   # dev sample; enable and terminate TLS 1.3 for any real deployment
    cert_file: ""
    key_file: ""
  max_body_bytes: 10485760   # 10 MiB — larger requests are rejected with 413

rate_limit:
  enabled: true
  key: "api_key"       # "api_key", falling back to "ip" on unauthenticated routes
  requests_per_min: 600
  burst: 60
  store: "memory"      # "memory" (single instance) or "redis" (Phase 3)

auth:
  api_key:
    enabled: true
    header: "X-API-Key"
  jwt:              # Phase 3 — not present in the Phase 1 MVP binary
    enabled: false
    jwks_url: "https://auth.example.com/.well-known/jwks.json"
    issuer: "https://auth.example.com"
    audience: "noject-gateway"

waf:
  max_inspect_bytes: 1048576   # scan at most 1 MiB of body
  oversize_action: "BLOCK"     # "BLOCK" (fail-closed) or "SKIP" (forward, audit the omission)

guard_engine:
  endpoint: "localhost:50051"
  timeout_ms: 1500
  fallback_action: "BLOCK" # default when the guard fails; override per route

routes:
  - id: "openai-proxy"
    path: "/v1/chat/completions"
    upstream: "https://api.openai.com/v1/chat/completions"
    type: "llm"
    auth_required: true
    fallback_action: "BLOCK"   # fail-closed: high-risk route
    guardrails:
      fast_waf: false
      prompt_injection: true
      jailbreak: true
      pii_masking: true
      pii_unmask_response: true      # substitute originals back before the client sees the body
      output_guard: true
      output_guard_mode: "streaming" # "streaming" (keeps TTFT) or "buffered"

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
  rotate_max_mb: 128        # rotated files stay linked via prev_record_hash
  fsync_on_block: true      # never lose the record of a blocked request
  fsync_interval_ms: 1000   # batched durability for ALLOWED records
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
│   ├── ratelimit/           # Token Bucket (memory; Redis in Phase 3)
│   ├── router/              # Reverse Proxy & Upstream Router
│   ├── guardclient/         # gRPC Client to Python Guard (Phase 2)
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
├── LICENSE                  # Apache-2.0
├── Makefile                 # Build, Proto Gen, Test, Run
├── go.mod
└── go.sum
```

*Phase 1 needs only `cmd/`, `internal/{auth,waf,ratelimit,router,audit,config}`, `configs/`, `deployments/`, `docs/`. `proto/` and `guard-engine/` arrive with Phase 2.*

---

## 7. Phased Delivery (MVP First)

The full architecture above is the target state, not the first release. Shipping the dual-engine, gRPC, multi-auth, ML-model system in one go maximizes cost before a single user has validated the product. Build the smallest thing that proves the value, then add layers when a measured limit forces it.

### Phase 1 — Single-binary MVP (prove the value)
- **One language (Go), one process.** No gRPC, no second runtime to deploy.
- **Reverse proxy** (`net/http`) with per-route config and SSE streaming pass-through.
- **One auth method:** API key (SHA-256).
- **Guardrails are heuristic-only, in-process:** regex/signature WAF for REST routes; keyword + pattern prompt-injection and PII rules for LLM routes. No ONNX/DeBERTa/embeddings yet.
- **Audit log:** JSON Lines + SHA-256 hash-chaining (cheap, keep it; single-writer/single-node is fine here).
- **Config + Docker Compose** for one-click launch.

*Deferred out of Phase 1 (add when heuristics measurably fall short / a real need appears):* Python guard engine + gRPC/UDS, ONNX/transformer classifiers and semantic embeddings, JWT/OIDC and HMAC auth, Redis-backed rate limiting and key store, buffered `output_guard_mode`.

### Phase 2 — AI guard engine
- Split the guard into the Python gRPC service (`guard-engine/`) **only once** heuristics prove insufficient and you can measure the gap.
- Add ML classifiers, semantic detection, streaming output inspection.
- Make `guard_engine.fallback_action` a **per-route** policy (fail-closed for high-risk routes, fail-open for availability-sensitive ones) rather than one global switch.

### Phase 3 — Enterprise / scale
- JWT/OIDC + HMAC auth, Redis rate limiting and distributed key store.
- Horizontal-scaling story for the audit chain (per-instance chains + external anchoring, or a single append service). Note: hash-chaining serializes writes and does not scale across instances by itself — document this constraint explicitly.
- Metrics (Prometheus), health/readiness endpoints, graceful shutdown.

---

## 8. Verification & Testing Strategy

1. **Unit Testing**:
   - Go: Auth validators, WAF pattern matching, rate limiter, and audit hash chaining.
   - Python (Phase 2): Prompt injection payloads, jailbreak permutations, PII masking accuracy.
2. **False-Positive Testing (as important as detection)**:
   - A corpus of *benign* traffic — JSON bodies containing prose, markdown, shell snippets, file paths, regexes, SQL keywords in ordinary sentences — asserted to pass unblocked. A WAF that blocks real traffic gets switched off, which is worse than no WAF. Track and gate on a false-positive rate, not only a detection rate.
3. **Streaming Output Guard Testing**:
   - Canary token split across chunk boundaries must still be detected (sliding-window correctness).
   - Stream is cut on detection, and the audit record is written for the cut.
   - PII placeholders spanning chunk boundaries are correctly substituted back (§4.2).
   - Time-to-first-token overhead measured against a no-guard baseline.
4. **Bounded-Input Testing**:
   - Oversized bodies hit `max_body_bytes` (`413`) and `max_inspect_bytes` (`oversize_action`) instead of consuming unbounded memory or CPU.
5. **Integration Testing**:
   - End-to-end proxy tests: valid and malicious requests asserted against `403 Forbidden` / `200 OK` and the resulting audit entries.
6. **ISO Audit Verification**:
   - Script verifying the SHA-256 chain across rotated files, from the zero genesis hash forward, with zero broken links. Must distinguish a *truncated* chain (tail loss, acceptable) from a *broken* one (tampering).
7. **Performance Benchmark**:
   - Throughput and latency overhead of the Go fast path (< 2ms) and, once it exists, the AI guard (< 100ms for lightweight local models).

---

## 9. Open Source & Community Readiness

- Fully containerized with `docker-compose.yml`.
- **Licensed Apache-2.0.** Chosen over MIT for its explicit patent grant and trademark clause, which enterprise security teams generally require before adopting an infrastructure component. A `LICENSE` file ships in the repository root from the first commit.
- Clear documentation for configuring downstream LLM APIs (OpenAI, Claude, Ollama) and custom REST APIs.
- Honest capability claims: the README states which phase each feature belongs to, so nobody deploys the MVP expecting model-based detection.
