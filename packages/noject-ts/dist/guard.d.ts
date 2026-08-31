import { GuardOptions, GuardVerdict, WAFVerdict } from './types';
import { WAFEngine } from './waf';
import { PromptInjectionDetector } from './ai/promptInjection';
import { JailbreakDetector } from './ai/jailbreak';
import { PIIMasker } from './ai/piiMasker';
import { CanaryShield } from './ai/canaryShield';
export declare class NoJectGuard {
    waf: WAFEngine | null;
    promptInjection: PromptInjectionDetector | null;
    jailbreak: JailbreakDetector | null;
    piiMasker: PIIMasker | null;
    canaryShield: CanaryShield;
    constructor(options?: GuardOptions);
    /**
     * Inspect an AI prompt for Prompt Injections, Jailbreaks, and PII.
     */
    inspectPrompt(prompt: string): GuardVerdict;
    /**
     * Mask Thai National IDs, phone numbers, emails, credit cards, and secret keys.
     */
    maskPII(text: string): string;
    /**
     * Inspect LLM response output for canary secret leakages.
     */
    inspectOutput(responseText: string, canaryTokens: string[]): GuardVerdict;
    /**
     * Standalone WAF Inspector for Web Requests (Path, Query, Headers, Body).
     */
    inspectRequest(input: string): WAFVerdict;
}
//# sourceMappingURL=guard.d.ts.map