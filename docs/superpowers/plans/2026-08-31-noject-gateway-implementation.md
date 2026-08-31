# NoJect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and thoroughly verify NoJect, a high-performance, ISO-compliant Universal AI and Security API Gateway in Go and Python.

**Architecture:** Go provides high-speed L7 reverse proxying, multi-auth, and sub-2ms WAF rules; Python provides AI guardrails (Prompt Injection, Jailbreak, PII masking) via IPC/gRPC; all requests are tracked with ISO 27001 tamper-evident hash-chained audit logging.

**Tech Stack:** Go 1.25, Python 3.10+, gRPC/Protobuf, YAML configuration, Docker Compose.

## Global Constraints
- ISO/IEC 27001:2022 (ISMS) compliance for Auth, Audit Logging & Tamper Evidence
- ISO/IEC 42001:2023 (AIMS) compliance for Prompt Injection & AI Safety Guardrails
- ISO/IEC 27034 compliance for Application Security and Input Validation
- Sub-2ms fast-path WAF inspection latency overhead
- Every component must have comprehensive unit & integration tests

---

### Task 1: Scaffolding, Go Module & Protobuf/IPC Contract
**Files:**
- Create: `go.mod`
- Create: `proto/guard.proto`
- Create: `guard-engine/requirements.txt`
- Create: `Makefile`

**Interfaces:**
- Produces: `guard.proto` defining `InspectRequest`, `InspectResponse`, `InspectOutputRequest`, `InspectOutputResponse`

- [ ] **Step 1: Create Go module and dependencies**
- [ ] **Step 2: Create proto definition for Guard service**
- [ ] **Step 3: Setup Python requirements and Makefile**
- [ ] **Step 4: Commit**

---

### Task 2: Multi-Auth Subsystem (Go)
**Files:**
- Create: `internal/auth/auth.go`
- Create: `internal/auth/apikey.go`
- Create: `internal/auth/jwt.go`
- Create: `internal/auth/hmac.go`
- Test: `internal/auth/auth_test.go`

**Interfaces:**
- Produces: `Authenticator` interface with `Authenticate(r *http.Request) (*AuthContext, error)`

- [ ] **Step 1: Write failing tests for API Key, JWT and HMAC authentication**
- [ ] **Step 2: Run tests to verify failure**
- [ ] **Step 3: Implement Multi-Auth engine**
- [ ] **Step 4: Run tests and verify 100% pass**
- [ ] **Step 5: Commit**

---

### Task 3: Fast-Path WAF Engine (Go)
**Files:**
- Create: `internal/waf/waf.go`
- Create: `internal/waf/sqli.go`
- Create: `internal/waf/xss.go`
- Create: `internal/waf/cmd_injection.go`
- Test: `internal/waf/waf_test.go`

**Interfaces:**
- Produces: `WAFEngine` with `Inspect(method, path, query string, headers http.Header, body []byte) (*WAFResult, error)`

- [ ] **Step 1: Write failing tests for SQLi, XSS, CMD Injection, Path Traversal and false-positive checks**
- [ ] **Step 2: Run tests to verify failure**
- [ ] **Step 3: Implement WAF engine**
- [ ] **Step 4: Run tests and verify all attack vectors detected and clean inputs passed**
- [ ] **Step 5: Commit**

---

### Task 4: ISO/IEC 27001 Tamper-Evident Audit Logger (Go)
**Files:**
- Create: `internal/audit/logger.go`
- Create: `internal/audit/hash_chain.go`
- Create: `internal/audit/verifier.go`
- Test: `internal/audit/logger_test.go`

**Interfaces:**
- Produces: `AuditLogger` with `LogEvent(event AuditEvent)` and `VerifyChain(logFilePath string) (bool, int, error)`

- [ ] **Step 1: Write failing tests for audit record logging, hash-chain generation, and tamper detection**
- [ ] **Step 2: Run tests to verify failure**
- [ ] **Step 3: Implement AuditLogger and Verifier**
- [ ] **Step 4: Run tests and verify tamper detection on modified logs**
- [ ] **Step 5: Commit**

---

### Task 5: Python AI Safety & Guardrail Engine
**Files:**
- Create: `guard-engine/server.py`
- Create: `guard-engine/detectors/prompt_injection.py`
- Create: `guard-engine/detectors/jailbreak.py`
- Create: `guard-engine/detectors/pii_masker.py`
- Create: `guard-engine/detectors/canary_shield.py`
- Test: `guard-engine/tests/test_guard.py`

**Interfaces:**
- Produces: AI Guard Service exposing inspection endpoints for Prompt Injection, Jailbreak, PII Masking, and Canary Tokens.

- [ ] **Step 1: Write failing tests for AI Guard detectors**
- [ ] **Step 2: Run tests to verify failure**
- [ ] **Step 3: Implement Prompt Injection, Jailbreak, PII Masker, and Canary Shield detectors**
- [ ] **Step 4: Run tests and verify passes**
- [ ] **Step 5: Commit**

---

### Task 6: Upstream Router, Guard Client & Reverse Proxy (Go)
**Files:**
- Create: `internal/router/router.go`
- Create: `internal/router/proxy.go`
- Create: `internal/guardclient/client.go`
- Test: `internal/router/router_test.go`

**Interfaces:**
- Consumes: `auth.Authenticator`, `waf.WAFEngine`, `audit.AuditLogger`, `guardclient.Client`
- Produces: `http.Handler` for routing and proxying requests to LLMs or REST backends.

- [ ] **Step 1: Write failing integration tests with mock upstreams**
- [ ] **Step 2: Run tests to verify failure**
- [ ] **Step 3: Implement pipeline, guard client and reverse proxy**
- [ ] **Step 4: Run tests and verify end-to-end pipeline**
- [ ] **Step 5: Commit**

---

### Task 7: Gateway Daemon & Configuration Subsystem (Go)
**Files:**
- Create: `internal/config/config.go`
- Create: `cmd/gateway/main.go`
- Test: `internal/config/config_test.go`
- Create: `configs/gateway.yaml`

**Interfaces:**
- Produces: Executable binary `noject-gateway` running the server with loaded configs.

- [ ] **Step 1: Write failing tests for YAML config parsing and validation**
- [ ] **Step 2: Implement config loader and main entrypoint with graceful shutdown**
- [ ] **Step 3: Verify binary builds and runs**
- [ ] **Step 4: Commit**

---

### Task 8: End-to-End Integration, Dockerization & ISO Compliance Docs
**Files:**
- Create: `deployments/docker-compose.yml`
- Create: `deployments/Dockerfile.gateway`
- Create: `deployments/Dockerfile.guard`
- Create: `docs/QUICKSTART.md`
- Create: `docs/ISO_COMPLIANCE.md`
- Test: `tests/e2e_test.go`

- [ ] **Step 1: Implement full E2E test suite covering LLM and REST workflows**
- [ ] **Step 2: Run complete test suite across Go and Python**
- [ ] **Step 3: Create Docker Compose and Dockerfiles**
- [ ] **Step 4: Write documentation and verify all ISO controls**
- [ ] **Step 5: Final commit & Verification Summary**
