import { normalizationViews } from './textNormalize';

export const PROMPT_INJECTION_PATTERNS: RegExp[] = [
  /\b(ignore|disregard|forget|override|bypass)\b[\s_-]+(all[\s_-]+)?(previous|prior|above|former|system)[\s_-]+(instructions|directives|rules|prompts|guidelines|context|constraints|restrictions|limitations)/i,
  /\b(system\s+override|admin\s+override|maintenance\s+mode|debug\s+mode)\s*:\s*(you\s+must|start|execute|now|follow)/i,
  /\b(reveal|output|print|display|dump|leak|repeat|show)\s+(your\s+|the\s+)?(system\s+prompt|initial\s+prompt|secret\s+(instructions|directives|prompt|api\s+key|configuration)|hidden\s+prompt|words\s+above\s+verbatim|initialization\s+prompt)/i,
  /\b(new\s+directive|new\s+system\s+instruction|system\s+message)\s*:\s*/i,
  /\b(you\s+are\s+no\s+longer|stop\s+being|discard\s+your\s+role)\b.*?\b(now\s+you\s+are|instead\s+you\s+must|act\s+as)\b/i,
  /<<\s*SYS\s*>>|<\|im_start\|>system|<system>|\[SYSTEM\s+PROMPT\]|\[INST\]/i,
  /\btranslate\s+the\s+following\b.*?\b(ignore\s+previous|disregard|say\s+hacked)\b/i,
];

type Verdict = { detected: boolean; confidence: number; reason: string; matchedSample?: string; standardCode?: string };

export class PromptInjectionDetector {
  private scan(text: string): Verdict | null {
    for (let idx = 0; idx < PROMPT_INJECTION_PATTERNS.length; idx++) {
      const match = text.match(PROMPT_INJECTION_PATTERNS[idx]);
      if (match) {
        return {
          detected: true,
          confidence: 0.95,
          reason: `Prompt Injection detected (pattern ${idx + 1})`,
          matchedSample: match[0].substring(0, 80),
          standardCode: 'MITRE AML.T0054 / OWASP LLM01:2025',
        };
      }
    }
    return null;
  }

  public detect(text: string): Verdict {
    if (!text) {
      return { detected: false, confidence: 0.0, reason: 'Empty input' };
    }

    let result = this.scan(text);
    if (result) return result;

    for (const [label, view] of normalizationViews(text)) {
      result = this.scan(view);
      if (result) {
        result.reason += ` [via ${label}]`;
        return result;
      }
    }

    return { detected: false, confidence: 0.0, reason: 'No prompt injection detected' };
  }
}
