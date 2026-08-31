# NoJect 🛡️ AI Agent Development & Context Guide (`AGENTS.md`)

Welcome, AI Agent / Assistant! This repository contains **NoJect (No-Injection)**: an open-source **Agentic AI Security Sentinel & API Gateway** engineered with a hybrid tiered defense architecture (Go Fast-Path WAF + Python/TypeScript Agentic AI Sentinel using LLM-as-a-Judge).

---

## 🧭 Core Project Mission & Philosophy

1. **Agentic AI Sentinel First**: NoJect is fundamentally an **Autonomous AI Security Sentinel** that uses LLM reasoning (LLM-as-a-Judge) for deep semantic threat detection, not just static regex rules.
2. **Hybrid Tiered Architecture**:
   - **Tier 1 (Go Ingress Core < 0.001 ms)**: Deterministic Fast-Path WAF for traditional web injections (SQLi, XSS, CMD, Path Traversal) and Multi-Auth (Argon2, JWT, HMAC).
   - **Tier 2 (Agentic AI Sentinel)**: Deep semantic intent analysis for Prompt Injections (`MITRE AML.T0054`), Jailbreaks (`AML.T0051`), Reconnaissance (`AML.T0043`), and PII Masking (`ISO 42001 Control B.7.2`).
   - **Tier 3 (Upstream & Egress)**: Upstream LLMs (OpenAI, Claude, Gemini, DeepSeek, Ollama/vLLM) + Outbound Canary Token Secret Shield + Cryptographic SHA-256 Hash Chained Audit Trail (`ISO 27001 Control A.8.15`).
3. **Dual Delivery Model**:
   - Standalone L7 Reverse Proxy Gateway (Go binary / Docker).
   - Embedded In-Process SDKs for Python (`packages/noject-python` with **Astral `uv`** & `pip`) and TypeScript/Node.js (`packages/noject-ts` with `npm`/`pnpm`/`bun`).
4. **Strict ISO Compliance Wording**: Always use the exact phrasing **"Architected in Alignment with ISO/IEC 27001:2022 & ISO/IEC 42001:2023 Principles"** and maintain the ISO Alignment Disclaimer.

---

## 📁 Repository Structure & Directory Map

```
NoJect/
├── cmd/
│   └── gateway/main.go            # Go Gateway Entrypoint (CLI flags, startup, router)
├── internal/
│   ├── audit/                      # Cryptographic SHA-256 Hash Chaining Audit Logger
│   ├── auth/                       # Multi-Auth Engine (Argon2 API Keys, JWT/OIDC, HMAC)
│   ├── config/                     # YAML Configuration Loader
│   ├── metrics/                    # Prometheus Metrics Exporter & Realtime SOC Dashboard
│   ├── proxy/                      # L7 Reverse Proxy & Dynamic Upstream Dispatcher
│   ├── ratelimit/                  # Token Bucket Rate Limiter
│   └── waf/                        # Sub-millisecond Regex & Lexical Fast WAF Engine
├── guard-engine/                   # Standalone Python AI Guardrail & Sentinel Service
│   ├── detectors/
│   │   ├── agentic_sentinel.py     # LLM-as-a-Judge Cognitive Security Sentinel Agent
│   │   ├── prompt_injection.py     # Semantic Prompt Injection Classifier
│   │   ├── jailbreak.py            # DAN & Roleplay Evasion Detector
│   │   ├── pii_masker.py           # Sensitive PII Anonymizer (Thai ID, Phone, CC, Email)
│   │   └── canary_shield.py        # Outbound Secret Leakage Defense
│   ├── benchmark.py                # Micro-benchmarks for Python Guardrail latency
│   ├── model_evaluator.py          # Multi-Model Defense Uplift Evaluator
│   ├── sentinel_benchmark.py       # Multi-Model LLM Sentinel Judge Benchmark
│   ├── server.py                   # FastAPI Guard Engine REST Server
│   └── tests/                      # Pytest Unit Test Suite
├── packages/
│   ├── noject-python/              # Standalone Python Library (PEP 517/621, Astral uv supported)
│   │   ├── pyproject.toml
│   │   ├── noject/                 # Core Python In-Process Guard, WAF, and Sentinel
│   │   │   ├── guard.py
│   │   │   ├── waf.py
│   │   │   ├── detectors/
│   │   │   └── integrations/fastapi.py
│   │   └── tests/test_lib.py
│   └── noject-ts/                  # Standalone TypeScript / Node.js Package (npm/pnpm/bun)
│       ├── package.json
│       ├── tsconfig.json
│       ├── src/
│       │   ├── guard.ts
│       │   ├── ai/                 # TS PromptInjection, Jailbreak, PII, AgenticSentinel
│       │   ├── waf/                # TS WAF Engine
│       │   └── middlewares/express.ts
│       └── tests/guard.test.ts
├── scripts/
│   ├── generate_infographic.py     # Generates docs/assets/noject_master_infographic.png
│   ├── generate_charts.py          # Generates security matrix & latency charts
│   └── generate_sentinel_charts.py # Generates docs/assets/sentinel_models_benchmark.png
├── configs/
│   └── gateway.yaml                # Default Gateway YAML Configuration
├── deployments/
│   ├── Dockerfile.gateway          # Multi-stage Go Gateway Dockerfile
│   ├── Dockerfile.guard            # Python Guard Engine Dockerfile
│   └── docker-compose.yml          # Full-stack Docker Compose setup
├── docs/                           # Comprehensive Documentation & Assets
│   ├── assets/                     # High-res Infographics & Benchmark Charts
│   ├── BENCHMARKS.md               # Empirical Performance & Accuracy Benchmark Data
│   ├── ISO_COMPLIANCE.md           # ISO 27001 & ISO 42001 Alignment Mapping
│   └── SECURITY_STANDARDS.md       # MITRE ATLAS & OWASP Top 10 Mapping
├── Makefile                        # Unified Build, Test, Benchmark, and Packaging runner
├── README.md                       # Master World-Class README
└── .env.example                    # Environment variable configuration template
```

---

## 🛠️ Build, Test, and Benchmark Commands

Always verify your changes by running the appropriate targets in `Makefile`:

```bash
# 1. Run the entire test suite across all 4 language targets (Go + Py Guard + Py Lib + TS Lib)
make test

# 2. Run all performance, latency, and model benchmark suites
make bench

# 3. Build all binaries and distributable packages (Go binary + Python wheel/sdist + TS bundle)
make all

# 4. Run sub-test suites individually:
make test-go            # Go unit & E2E tests
make test-guard         # Python guard-engine pytest
make test-py-lib        # Python library pytest (via uv run pytest)
make test-ts-lib        # TypeScript library tests (via npm test)
```

---

## 📌 Coding Conventions & Golden Rules for Agents

1. **Zero-Bypass Accuracy**: Do not weaken regex patterns or semantic heuristics. Ensure all 90 standard attack vector tests pass 100%.
2. **Sub-Millisecond Fast Path**: Keep Go Fast-Path WAF latency under **0.001 ms (1 µs)** and total Gateway pipeline under **0.009 ms (9 µs)**.
3. **Astral `uv` Compatibility**: Whenever modifying `packages/noject-python/`, ensure compatibility with both Astral `uv` (`uv add`, `uv run pytest`, `uv build`) and standard `pip`/`build`.
4. **TypeScript Strictness**: Keep TypeScript strict mode enabled (`noImplicitAny`, full `.d.ts` declaration generation).
5. **Deterministic Testing**: Write unit tests for any new detector, middleware, or configuration option.
6. **No Breaking Changes to Audit Log**: The SHA-256 hash chaining format in `internal/audit/logger.go` must remain verifiable by `./bin/noject-gateway -verify-audit`.

---

## 🚀 Next Milestone Tasks & Potential Features

If the user asks for new features or further development, here are the planned roadmap items:

- [ ] **gRPC Bidirectional Streaming Interface**: Add streaming gRPC inspection for ultra-high throughput LLM token streaming (SSE / chunks).
- [ ] **Modern React/Tailwind Web SOC UI**: Upgrade the embedded HTML dashboard (`internal/metrics/dashboard.go`) into a rich React SPA with live WebSocket threat telemetry.
- [ ] **Kubernetes Helm Chart & Envoy WASM Filter**: Package NoJect as a Kubernetes Ingress Controller and Envoy WASM filter for service mesh integration (Istio / Cilium).
- [ ] **Dynamic Zero-Day Rule Sync**: Cloud / GitHub action mechanism to automatically sync latest MITRE ATLAS threat feeds into local heuristics.
