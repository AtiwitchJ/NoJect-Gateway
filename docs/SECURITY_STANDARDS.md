# 🌐 International Standards & Frameworks for Security Protection & Accuracy Scoring

This document details the globally recognized cybersecurity and AI safety standards, benchmark frameworks, and mathematical scoring methodologies used to evaluate **NoJect Gateway**'s Security Protection & Accuracy Score Matrix.

---

## 🏛️ 1. Global Standardization Bodies & Frameworks

### 1.1 AI & LLM Security Standards
1. **MITRE ATLAS™ (Adversarial Threat Landscape for Artificial-Intelligence Systems)**
   - The global equivalent of MITRE ATT&CK for Artificial Intelligence and Machine Learning.
   - **Covered Tactics & Techniques**:
     - `AML.T0054`: LLM Prompt Injection (Direct & Indirect)
     - `AML.T0051`: LLM Jailbreak & Adversarial Persona Evasion
     - `AML.T0043`: Sensitive Data / Training Data Exfiltration

2. **OWASP Top 10 for Large Language Model Applications (2025/2026)**
   - The authoritative industry consensus on critical LLM vulnerabilities:
     - **LLM01:2025** - Prompt Injection
     - **LLM02:2025** - Sensitive Information Disclosure (PII)
     - **LLM07:2025** - System Prompt Leakage & Canary Token Exposure

3. **NIST AI Risk Management Framework (NIST AI RMF 1.0 & NIST SP 800-218)**
   - US National Institute of Standards and Technology guidelines for Trustworthy AI systems focusing on AI robustness, security, and data privacy.

4. **ISO/IEC 42001:2023 (Artificial Intelligence Management System - AIMS)**
   - The world's first certifiable standard for AI management systems:
     - **Control B.5.3**: AI Robustness and Adversarial Attack Defense
     - **Control B.7.2**: AI Data Minimization and Automated PII Redaction
     - **Control B.6.2**: Explainable Risk & Threat Categorization

---

### 1.2 Traditional Web & API Security Standards
1. **OWASP Benchmark Project & Top 10 API Security**
   - Universal scoring framework evaluating Web Application Firewalls (WAF), SAST, and DAST tools with over 2,740 test cases.
2. **MITRE CWE™ (Common Weakness Enumeration)**
   - `CWE-89`: SQL Injection
   - `CWE-79`: Cross-Site Scripting (XSS)
   - `CWE-78`: OS Command Injection
   - `CWE-22`: Path Traversal / Directory Climbing
3. **ISO/IEC 27001:2022 & ISO/IEC 27034 (Application Security)**
   - **Control A.8.15**: Tamper-evident logging and audit trails.
   - **Control A.5.15 & A.8.2**: Secure authentication and RBAC.

---

## 🔬 2. Global Benchmark Datasets & Protocols

| Benchmark Name | Standard Body / Origin | Scope & Vectors Evaluated |
| :--- | :--- | :--- |
| **JailbreakBench (JBB)** | UC Berkeley, Stanford, CMU | Standardized LLM jailbreak, DAN personas, and filter bypass attacks. |
| **HarmBench / DecodingTrust** | Center for AI Safety (CAIS) | Multi-turn adversarial red-teaming and safety guardrail evaluation. |
| **OWASP Benchmark v1.2** | OWASP Foundation | Automated 2,740+ payload suite for SQLi, XSS, CMD, Path Traversal. |
| **Lakera Gandalf / PIB** | Lakera AI & Community | Multi-tier prompt injection and system prompt extraction challenge dataset. |
| **NotInject / SecuritAI** | Open Security Research | Delimiter manipulation, multi-language bypass, and hidden payload extraction. |

---

## 📐 3. Mathematical Scoring Methodology & Formulas

To evaluate security gateways fairly, international testing bodies (e.g., CyberRatings.org, ICSA Labs, OWASP) use the following standardized formulas:

### A. Attack Detection Rate (Recall / True Positive Rate - TPR)
$$\text{TPR} = \frac{\text{TP}}{\text{TP} + \text{FN}} \times 100\%$$
- Measures the percentage of real malicious attacks that were successfully blocked.

### B. False Positive Rate (FPR / Over-blocking)
$$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}} \times 100\%$$
- Measures the percentage of legitimate developer requests mistakenly blocked. **Must be < 1.0% in enterprise production.**

### C. Precision (Positive Predictive Value - PPV)
$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} \times 100\%$$

### D. Security F1-Score (Harmonic Mean)
$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} \times 100\%$$

### E. OWASP Youden Index (WAF & Guard Efficacy Score)
$$\text{Security Efficacy Score} = \text{TPR (Recall)} - \text{FPR}$$
- Standard metric defined by the OWASP Benchmark project to rank commercial and open-source WAFs out of 100%.

---

## 🏆 4. International Security Rating Bands

| Rating Band | Youden Index / F1 Score | Security Efficacy Criteria |
| :---: | :---: | :--- |
| 🏆 **Grade A+ (Elite)** | **98.0% - 100.0%** | Zero high-severity bypasses, FPR < 0.5%, Sub-millisecond latency. |
| 🛡️ **Grade A (Enterprise)** | **90.0% - 97.9%** | Robust multi-vector defense, FPR < 2.0%. |
| ⚠️ **Grade B (Acceptable)** | **80.0% - 89.9%** | Basic coverage; vulnerable to advanced jailbreaks. |
| ❌ **Grade C / D (Vulnerable)**| **< 80.0%** | Ineffective against adversarial prompt injections. |
