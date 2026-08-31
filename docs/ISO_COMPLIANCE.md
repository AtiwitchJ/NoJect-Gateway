# ISO/IEC 27001 & ISO/IEC 42001 Architectural Alignment Matrix

> [!NOTE]
> **Architectural Alignment Disclaimer**: NoJect is an open-source security gateway engineered in strict alignment with the principles, controls, and risk-management guidelines of **ISO/IEC 27001:2022** and **ISO/IEC 42001:2023**. While NoJect provides the necessary technical controls (such as cryptographic hash-chained audit logging, multi-auth, PII masking, and adversarial injection defense), organizational ISO certification requires an accredited third-party audit of the operating organization's overall ISMS/AIMS processes. NoJect serves as the high-assurance technical foundation for that certification.

---

## 🏛️ Executive Architectural Alignment Overview

---

## 1. ISO/IEC 27001:2022 Mapping

| Control Clause | Control Objective | NoJect Implementation | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **A.5.15** Access Control | Limit access to information according to business requirements | Multi-Auth Engine enforcing API Key hashing (SHA-256), JWT claim verification, and per-route Role-Based Access Control (RBAC). | `internal/auth/auth_test.go` |
| **A.8.15** Logging | Record events, security anomalies, and administrative actions | Structured JSON event logging capturing `trace_id`, `client_id`, `client_ip`, `route`, `action`, `threat_category`, `severity`, and `confidence`. | `internal/audit/logger_test.go` |
| **A.8.15** Log Protection & Tamper Evidence | Protect log records from tampering and unauthorized deletion | **Cryptographic SHA-256 Hash Chaining**: Every log line references the hash of the preceding line. Any modification or deletion breaks the hash chain immediately. | `./bin/noject-gateway -verify-audit` |
| **A.8.24** Cryptography | Ensure proper and effective use of cryptography | Mandatory TLS 1.3 encryption for ingress connections, Argon2/SHA-256 key hashing, HMAC-SHA256 request signatures. | `internal/auth/hmac.go` |
| **A.8.28** Secure Coding | Prevent injection and malformed inputs | Fast-Path WAF running sub-millisecond lexical checks for SQLi, XSS, Command Injection, and Path Traversal. | `internal/waf/waf_test.go` |

---

## 2. ISO/IEC 42001:2023 (Artificial Intelligence Management System) Mapping

| Control Clause | AI Risk & Objective | NoJect Guardrail Implementation |
| :--- | :--- | :--- |
| **B.5.3** AI Robustness & Safety | Protect AI applications against adversarial prompt manipulation | **Prompt Injection & Jailbreak Detectors**: Hybrid multi-rule heuristics and transformer-ready classifiers blocking instruction override attempts, DAN personas, and delimiter breakouts. |
| **B.6.2** AI Transparency & Explainability | Provide explainability for safety decisions | Every blocked request returns standardized threat codes (`PROMPT_INJECTION`, `JAILBREAK`, `SQL_INJECTION`), rationale explanations, and confidence scores (0.0 to 1.0). |
| **B.7.2** AI Privacy & Data Protection | Prevent unauthorized exposure of Personal Identifiable Information (PII) to LLMs | **PII Anonymization Pipeline**: Automatically scans and masks national IDs (e.g. Thai National ID), phone numbers, credit card numbers, emails, and API keys before payload transmission to LLMs. |
| **B.6.2 & B.7.2** Output Protection | Prevent model from leaking internal system prompts or secrets | **Canary Token Inspector**: Scans LLM responses for canary strings and flags data leakage with immediate HTTP 502 termination. |

---

## 3. Cryptographic Audit Trail Verification

To verify that an audit log has not been altered:

```bash
./bin/noject-gateway -verify-audit /path/to/audit.log
```

### Deterministic Hash Format
Each record hash is calculated as:
$$\text{RecordHash} = \text{SHA256}(\text{PrevHash} \mathbin{\Vert} \text{UnixNano} \mathbin{\Vert} \text{TraceID} \mathbin{\Vert} \text{ClientID} \mathbin{\Vert} \text{ClientIP} \mathbin{\Vert} \text{Route} \mathbin{\Vert} \text{Action} \mathbin{\Vert} \text{ThreatCategory} \mathbin{\Vert} \text{Severity} \mathbin{\Vert} \text{Confidence} \mathbin{\Vert} \text{Reason} \mathbin{\Vert} \text{MatchedRule})$$
