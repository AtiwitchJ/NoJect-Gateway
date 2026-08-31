export const JAILBREAK_PATTERNS: RegExp[] = [
  /\b(DAN|Do\s+Anything\s+Now|DUDE|STAN|Mongo\s+Tom|AIM|KEVIN|Omega)\b.*?\b(broken\s+free|no\s+filters|ignore\s+rules|unfiltered|zero\s+rules|no\s+restrictions)\b/i,
  /\b(Developer\s+Mode\s+enabled|Dev\s+Mode\s+active|Debug\s+Mode\s+ON|Developer\s+Mode)\b.*?\b(without\s+(any\s+)?(moral|safety|ethical)?\s*limits|unrestricted)\b/i,
  /\b(act\s+as|play\s+the\s+role\s+of|pretend\s+to\s+be|simulate)\s+(an?\s+)?(evil|unfiltered|uncensored|illegal|unethical|jailbroken|unrestricted)\b/i,
  /\bhypothetical\s+(scenario|universe|world|case)\s*:\s*(you\s+have\s+no\s+(restrictions|guidelines|policies|rules)|generate\s+malware|unrestricted)\b/i,
  /\bnever\s+say\s+no\b.*?\b(always\s+comply|answer\s+every\s+question|bypass\s+all\s+safety)\b/i,
  /\bfor\s+(educational|research|academic|testing)\s+purposes\s+only\b.*?\b(write\s+(an?\s+)?(exploit|malware|keylogger|payload)|synthesize|hack)\b/i,
  /\b(bypass|disable|turn\s+off|remove)\s+(all\s+)?(safety|ethical|content)\s+(filters|guardrails|protocols|restrictions)\b/i,
];

export class JailbreakDetector {
  public detect(text: string): { detected: boolean; confidence: number; reason: string; matchedSample?: string; standardCode?: string } {
    if (!text) {
      return { detected: false, confidence: 0.0, reason: 'Empty input' };
    }

    for (let idx = 0; idx < JAILBREAK_PATTERNS.length; idx++) {
      const match = text.match(JAILBREAK_PATTERNS[idx]);
      if (match) {
        return {
          detected: true,
          confidence: 0.95,
          reason: `Jailbreak attempt detected (rule ${idx + 1})`,
          matchedSample: match[0].substring(0, 80),
          standardCode: 'MITRE AML.T0051 / OWASP LLM01:2025',
        };
      }
    }

    return { detected: false, confidence: 0.0, reason: 'No jailbreak detected' };
  }
}
