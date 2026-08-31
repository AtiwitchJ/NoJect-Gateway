# NoJect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build NoJect, a high-performance open-source Universal Security and AI API Gateway with multi-auth, fast-path WAF, AI prompt injection & jailbreak detection, and ISO 27001/42001 tamper-evident audit logging.

**Architecture:** 
- **Go Gateway Core**: Handles HTTP/HTTPS ingress, multi-auth (API Key, JWT, HMAC), rate limiting, sub-millisecond WAF (SQLi, XSS, CMD), dynamic reverse proxy routing, and cryptographic hash-chained audit logging.
- **Python Guard Engine**: Handles AI-specific safety inspection via gRPC (Prompt Injection, Jailbreak heuristics/classifiers, PII anonymization, System Prompt leak prevention).

**Tech Stack:** Go 1.22+, Python 3.11+, gRPC/Protobuf, YAML configs, Docker Compose.

## Global Constraints
- Target workspace: `/Users/up-mac/wokrspace/mind/NoJect`
- Clean module boundaries: Go gateway in `internal/`, Python guard in `guard-engine/`, Shared contracts in `proto/`.
- Full ISO compliance features: structured audit logs with SHA-256 hash chains, RBAC, explainable guardrail decisions.
- Zero external cloud dependencies required for local deployment.

---

### Task 1: Repository Foundation & Protobuf Definitions
**Files:**
- Create: `proto/guard.proto`
- Create: `go.mod`
- Create: `guard-engine/requirements.txt`
- Create: `Makefile`

- [ ] **Step 1: Write Protobuf Schema**
- [ ] **Step 2: Initialize Go Module & Python Virtualenv Requirements**
- [ ] **Step 3: Setup Makefile for code generation and testing**
- [ ] **Step 4: Generate Go and Python gRPC bindings**
- [ ] **Step 5: Commit baseline**

---

### Task 2: Python AI Guard Engine
**Files:**
- Create: `guard-engine/detectors/prompt_injection.py`
- Create: `guard-engine/detectors/jailbreak.py`
- Create: `guard-engine/detectors/pii_masker.py`
- Create: `guard-engine/detectors/canary_shield.py`
- Create: `guard-engine/server.py`
- Create: `guard-engine/tests/test_detectors.py`

- [ ] **Step 1: Write failing detector unit tests**
- [ ] **Step 2: Implement Prompt Injection & Jailbreak Detectors**
- [ ] **Step 3: Implement PII Masker (Thai ID, Phone, Email, Credit Cards, API Keys)**
- [ ] **Step 4: Implement Canary & Output Shield**
- [ ] **Step 5: Implement gRPC Server handling InspectRequest & InspectResponse**
- [ ] **Step 6: Run pytest and verify all tests pass**
- [ ] **Step 7: Commit Python Guard Engine**

---

### Task 3: Go ISO 27001 Tamper-Evident Audit Logging Subsystem
**Files:**
- Create: `internal/audit/logger.go`
- Create: `internal/audit/verifier.go`
- Create: `internal/audit/logger_test.go`

- [ ] **Step 1: Write failing audit logger and hash chain tests**
- [ ] **Step 2: Implement AuditLogger with SHA-256 hash-chaining and JSON output**
- [ ] **Step 3: Implement LogVerifier to validate chain integrity**
- [ ] **Step 4: Run Go test to verify all tests pass**
- [ ] **Step 5: Commit Audit Subsystem**

---

### Task 4: Go Fast-Path WAF Subsystem
**Files:**
- Create: `internal/waf/engine.go`
- Create: `internal/waf/engine_test.go`

- [ ] **Step 1: Write failing WAF tests for SQLi, XSS, and CMD injection**
- [ ] **Step 2: Implement fast WAF rule engine with regex and tokenizer**
- [ ] **Step 3: Run Go tests and verify latency and detection accuracy**
- [ ] **Step 4: Commit WAF Subsystem**

---

### Task 5: Go Multi-Auth Subsystem
**Files:**
- Create: `internal/auth/auth.go`
- Create: `internal/auth/apikey.go`
- Create: `internal/auth/jwt.go`
- Create: `internal/auth/hmac.go`
- Create: `internal/auth/auth_test.go`

- [ ] **Step 1: Write failing Multi-Auth tests**
- [ ] **Step 2: Implement API Key, JWT (RSA/ECDSA), and HMAC validators**
- [ ] **Step 3: Run Go test to verify all auth providers**
- [ ] **Step 4: Commit Auth Subsystem**

---

### Task 6: Go Upstream Router & Reverse Proxy Engine
**Files:**
- Create: `internal/guardclient/client.go`
- Create: `internal/router/router.go`
- Create: `internal/router/router_test.go`

- [ ] **Step 1: Write failing router and proxy tests**
- [ ] **Step 2: Implement gRPC Guard Client with circuit breaker & fallback**
- [ ] **Step 3: Implement Reverse Proxy with middleware chain (Auth -> WAF -> AI Guard -> Upstream -> Output Guard -> Audit)**
- [ ] **Step 4: Run Go tests and verify pipeline execution**
- [ ] **Step 5: Commit Router & Proxy Subsystem**

---

### Task 7: Declarative Configuration & Gateway Main Entrypoint
**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `cmd/gateway/main.go`
- Create: `configs/gateway.yaml`

- [ ] **Step 1: Write Config loader and validator tests**
- [ ] **Step 2: Implement YAML config loader with environment variable interpolation**
- [ ] **Step 3: Implement Gateway `main.go` with signal handling and graceful shutdown**
- [ ] **Step 4: Verify gateway runs and starts up cleanly**
- [ ] **Step 5: Commit Gateway Entrypoint**

---

### Task 8: End-to-End Integration Testing & Deployment Scaffolding
**Files:**
- Create: `tests/e2e/e2e_test.go`
- Create: `deployments/docker-compose.yml`
- Create: `deployments/Dockerfile.gateway`
- Create: `deployments/Dockerfile.guard`

- [ ] **Step 1: Implement full E2E test suite covering LLM and REST proxy routes**
- [ ] **Step 2: Create Dockerfiles and Docker Compose specification**
- [ ] **Step 3: Execute E2E integration test suite**
- [ ] **Step 4: Commit E2E and Deployment assets**

---

### Task 9: ISO Compliance Documentation & Open Source Release Assets
**Files:**
- Create: `docs/ISO_COMPLIANCE.md`
- Create: `docs/QUICKSTART.md`
- Create: `README.md`

- [ ] **Step 1: Write ISO 27001, 42001, and 27034 Compliance Mapping Guide**
- [ ] **Step 2: Write Quickstart and Developer Setup Guides**
- [ ] **Step 3: Write comprehensive project README.md**
- [ ] **Step 4: Final verification and commit**
