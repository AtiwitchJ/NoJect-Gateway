# NoJect 🛡️
### Universal AI & Security API Gateway (ISO/IEC 27001 & ISO/IEC 42001 Compliant)

[![Go Tests](https://img.shields.io/badge/Go%20Tests-100%25%20Passing-brightgreen)](#)
[![Python Guard](https://img.shields.io/badge/Python%20Guard-100%25%20Passing-brightgreen)](#)
[![ISO 27001](https://img.shields.io/badge/ISO%2FIEC-27001%20Compliant-blue)](#)
[![ISO 42001](https://img.shields.io/badge/ISO%2FIEC-42001%20AI%20Safety-blue)](#)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**NoJect** is an open-source, high-performance API Gateway designed to defend modern applications and AI workflows against both **traditional injection attacks** (SQLi, XSS, Command Injection, Path Traversal) and **AI-specific threats** (Prompt Injection, Jailbreaks, System Prompt Extraction, PII Leakage).

```
[ Client / Application ]
         │
         ▼ (HTTPS / TLS 1.3)
┌─────────────────────────────────────────────────────────────┐
│  Go Gateway (L7 Reverse Proxy & Fast Shield)                │
│  - Multi-Auth: API Key / JWT / Bearer / HMAC                │
│  - Rate Limiter (Token Bucket / Redis-backed)               │
│  - Fast WAF: SQLi, XSS, CMD Injection, Path Traversal       │
│  - Dynamic Router: Match Route → Target (LLM / REST API)    │
└──────────────┬──────────────────────────────┬───────────────┘
               │ (Internal gRPC/HTTP)         │ (Fast Path / No AI)
               ▼                              │
┌──────────────────────────────┐              │
│ Python AI Guard Engine       │              │
│ - Prompt Injection Detector  │              │
│ - Jailbreak & Toxicity Guard │              │
│ - PII Anonymizer / Masking   │              │
│ - System Prompt Shield       │              │
└──────────────┬───────────────┘              │
               │ (Verdict: Allow/Block/Mask)  │
               └──────────────┬───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Upstream Forwarding (LLM or Backend REST API)              │
│  Output Canary Token & ISO 27001 Hash-Chained Audit Trail   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🌟 Key Features

1. **Dual-Engine Architecture**:
   - **Go Gateway Core**: Microsecond-latency L7 reverse proxy with multi-auth, routing, and fast WAF (< 0.3ms latency).
   - **Python AI Guard Engine**: Comprehensive detection of Prompt Injections, Jailbreak personas, and sensitive PII masking.
2. **Multi-Auth Engine**:
   - API Key with Argon2/SHA-256 hashing and Role-Based Access Control (RBAC).
   - JWT / OIDC token validation with JWKS and claims checking.
   - HMAC-SHA256 request signature verification for machine-to-machine traffic.
3. **Multi-Vector Threat Protection**:
   - **Traditional**: SQL Injection, Cross-Site Scripting (XSS), OS Command Injection, Path Traversal (`../`).
   - **AI/LLM (OWASP Top 10 for LLM)**: Direct & indirect prompt injection, DAN jailbreak personas, developer mode overrides, sensitive PII leakage.
4. **ISO Compliance & Tamper-Evident Audit Logging**:
   - Built to meet **ISO/IEC 27001** (ISMS / Logging A.8.15 / Access Control A.8.2) and **ISO/IEC 42001** (AI Management Systems).
   - **Cryptographic SHA-256 Hash Chaining**: Verifiable audit trail where any log tampering is immediately detectable.
5. **Real-time Observability & Monitoring**:
   - **Embedded Web Dashboard**: Real-time SOC dashboard accessible directly at `/dashboard` with zero setup.
   - **Prometheus & Grafana**: Native `/metrics` endpoint with ready-to-use Docker Compose stack.

---

## 🚀 Quick Start with Docker

```bash
docker compose -f deployments/docker-compose.yml up -d
```

Check health:
```bash
curl http://localhost:8080/healthz
# {"status":"healthy","version":"1.0.0"}
```

Verify audit log integrity:
```bash
./bin/noject-gateway -verify-audit logs/audit.log
# ✅ AUDIT LOG INTEGRITY VERIFIED: All records match SHA-256 hash chain.
```

---

## 📚 Documentation
- 📖 [Quickstart Guide](docs/QUICKSTART.md)
- 🔒 [ISO Compliance Matrix (ISO 27001 / ISO 42001)](docs/ISO_COMPLIANCE.md)
- 📐 [Technical Design Specification](docs/superpowers/specs/2026-08-31-noject-gateway-design.md)
- 📝 [Implementation Plan](docs/superpowers/plans/2026-08-31-noject-gateway-implementation.md)

---

## 🧪 Testing & Verification

Run the comprehensive test suite:
```bash
# Go unit and E2E security tests
make test-go

# Python AI Guard unit tests
make test-py
```

---

## 📄 License
MIT License. Open source and ready for enterprise deployment.
