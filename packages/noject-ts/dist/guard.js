"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NoJectGuard = void 0;
const waf_1 = require("./waf");
const promptInjection_1 = require("./ai/promptInjection");
const jailbreak_1 = require("./ai/jailbreak");
const piiMasker_1 = require("./ai/piiMasker");
const canaryShield_1 = require("./ai/canaryShield");
class NoJectGuard {
    waf;
    promptInjection;
    jailbreak;
    piiMasker;
    canaryShield;
    constructor(options) {
        const enableWAF = options?.enableWAF ?? true;
        const enableAI = options?.enableAIGuard ?? true;
        const enablePII = options?.enablePIIMasking ?? true;
        this.waf = enableWAF ? new waf_1.WAFEngine() : null;
        this.promptInjection = enableAI ? new promptInjection_1.PromptInjectionDetector() : null;
        this.jailbreak = enableAI ? new jailbreak_1.JailbreakDetector() : null;
        this.piiMasker = enablePII ? new piiMasker_1.PIIMasker() : null;
        this.canaryShield = new canaryShield_1.CanaryShield();
    }
    /**
     * Inspect an AI prompt for Prompt Injections, Jailbreaks, and PII.
     */
    inspectPrompt(prompt) {
        if (!prompt) {
            return { isBlocked: false, threatCategory: 'NONE', confidence: 0.0 };
        }
        // 1. Check Fast WAF (SQLi / CMD in prompt)
        if (this.waf) {
            const wafRes = this.waf.inspect(prompt);
            if (wafRes.blocked) {
                return {
                    isBlocked: true,
                    threatCategory: wafRes.threatType,
                    reason: wafRes.reason,
                    standardCode: wafRes.standardCode,
                    confidence: wafRes.confidence,
                };
            }
        }
        // 2. Check Prompt Injection (MITRE AML.T0054)
        if (this.promptInjection) {
            const piRes = this.promptInjection.detect(prompt);
            if (piRes.detected) {
                return {
                    isBlocked: true,
                    threatCategory: 'PROMPT_INJECTION',
                    reason: piRes.reason,
                    standardCode: piRes.standardCode,
                    confidence: piRes.confidence,
                    matchedSample: piRes.matchedSample,
                };
            }
        }
        // 3. Check Jailbreak / Persona Evasion (MITRE AML.T0051)
        if (this.jailbreak) {
            const jbRes = this.jailbreak.detect(prompt);
            if (jbRes.detected) {
                return {
                    isBlocked: true,
                    threatCategory: 'JAILBREAK',
                    reason: jbRes.reason,
                    standardCode: jbRes.standardCode,
                    confidence: jbRes.confidence,
                    matchedSample: jbRes.matchedSample,
                };
            }
        }
        // 4. Check PII Masking (ISO 42001 B.7.2)
        let maskedText = prompt;
        let hasPii = false;
        let entitiesFound = [];
        if (this.piiMasker) {
            const piiRes = this.piiMasker.mask(prompt);
            maskedText = piiRes.maskedText;
            hasPii = piiRes.hasPii;
            entitiesFound = piiRes.entitiesFound;
        }
        return {
            isBlocked: false,
            threatCategory: 'NONE',
            confidence: 0.0,
            maskedText,
            hasPii,
            entitiesFound,
        };
    }
    /**
     * Mask Thai National IDs, phone numbers, emails, credit cards, and secret keys.
     */
    maskPII(text) {
        if (!this.piiMasker || !text)
            return text;
        return this.piiMasker.mask(text).maskedText;
    }
    /**
     * Inspect LLM response output for canary secret leakages.
     */
    inspectOutput(responseText, canaryTokens) {
        const canaryRes = this.canaryShield.inspect(responseText, canaryTokens);
        if (canaryRes.leaked) {
            return {
                isBlocked: true,
                threatCategory: 'CANARY_LEAK',
                reason: canaryRes.reason,
                standardCode: canaryRes.standardCode,
                confidence: 1.0,
                matchedSample: canaryRes.matchedToken,
            };
        }
        return { isBlocked: false, threatCategory: 'NONE', confidence: 0.0 };
    }
    /**
     * Standalone WAF Inspector for Web Requests (Path, Query, Headers, Body).
     */
    inspectRequest(input) {
        if (!this.waf)
            return { blocked: false, threatType: 'NONE', confidence: 0.0 };
        return this.waf.inspect(input);
    }
}
exports.NoJectGuard = NoJectGuard;
//# sourceMappingURL=guard.js.map