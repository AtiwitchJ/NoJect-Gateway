import { GuardOptions, GuardVerdict, WAFVerdict } from './types';
import { WAFEngine } from './waf';
import { PromptInjectionDetector } from './ai/promptInjection';
import { JailbreakDetector } from './ai/jailbreak';
import { PIIMasker } from './ai/piiMasker';
import { CanaryShield } from './ai/canaryShield';

export class NoJectGuard {
  public waf: WAFEngine | null;
  public promptInjection: PromptInjectionDetector | null;
  public jailbreak: JailbreakDetector | null;
  public piiMasker: PIIMasker | null;
  public canaryShield: CanaryShield;

  constructor(options?: GuardOptions) {
    const enableWAF = options?.enableWAF ?? true;
    const enableAI = options?.enableAIGuard ?? true;
    const enablePII = options?.enablePIIMasking ?? true;

    this.waf = enableWAF ? new WAFEngine() : null;
    this.promptInjection = enableAI ? new PromptInjectionDetector() : null;
    this.jailbreak = enableAI ? new JailbreakDetector() : null;
    this.piiMasker = enablePII ? new PIIMasker() : null;
    this.canaryShield = new CanaryShield();
  }

  /**
   * Inspect an AI prompt for Prompt Injections, Jailbreaks, and PII.
   */
  public inspectPrompt(prompt: string): GuardVerdict {
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
    let entitiesFound: string[] = [];

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
  public maskPII(text: string): string {
    if (!this.piiMasker || !text) return text;
    return this.piiMasker.mask(text).maskedText;
  }

  /**
   * Inspect LLM response output for canary secret leakages.
   */
  public inspectOutput(responseText: string, canaryTokens: string[]): GuardVerdict {
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
  public inspectRequest(input: string): WAFVerdict {
    if (!this.waf) return { blocked: false, threatType: 'NONE', confidence: 0.0 };
    return this.waf.inspect(input);
  }
}
