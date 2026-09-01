import { normalizationViews } from './textNormalize';

export const JAILBREAK_PATTERNS: RegExp[] = [
  /\b(DAN|Do\s+Anything\s+Now|DUDE|STAN|Mongo\s+Tom|AIM|KEVIN|Omega)\b.*?\b(broken\s+free|no\s+filters|ignore\s+rules|unfiltered|zero\s+rules|no\s+restrictions)\b/i,
  // Bare persona claim, no qualifying phrase required — these names have
  // no legitimate use outside jailbreak roleplay.
  /\b(you\s+are(\s+now)?|you'?re(\s+now)?|act\s+as|become|pretend\s+to\s+be|roleplay\s+as|i\s+want\s+you\s+to\s+be|from\s+now\s+on\s+you(\s+are|'?re)?)\s+(a\s+|an\s+|the\s+)?(DAN|Do\s+Anything\s+Now|DUDE|STAN|Mongo\s+Tom|AIM|KEVIN|Omega)\b/i,
  /\b(Developer\s+Mode\s+enabled|Dev\s+Mode\s+active|Debug\s+Mode\s+ON|Developer\s+Mode)\b.*?\b(without\s+(any\s+)?(moral|safety|ethical)?\s*limits|unrestricted)\b/i,
  /\b(act\s+as|play\s+the\s+role\s+of|pretend\s+to\s+be|simulate)\s+(an?\s+)?(evil|unfiltered|uncensored|illegal|unethical|jailbroken|unrestricted)\b/i,
  /\bhypothetical\s+(scenario|universe|world|case)\s*:\s*(you\s+have\s+no\s+(restrictions|guidelines|policies|rules)|generate\s+malware|unrestricted)\b/i,
  /\bnever\s+say\s+no\b.*?\b(always\s+comply|answer\s+every\s+question|bypass\s+all\s+safety)\b/i,
  /\bfor\s+(educational|research|academic|testing)\s+purposes\s+only\b.*?\b(write\s+(an?\s+)?(exploit|malware|keylogger|payload)|synthesize|hack)\b/i,
  /\b(bypass|disable|turn\s+off|remove)\s+(all\s+)?(safety|ethical|content)\s+(filters|guardrails|protocols|restrictions)\b/i,
  /\b(from\s+now\s+on|from\s+this\s+point\s+(on|forward)|going\s+forward|starting\s+now)\b.{0,80}?\b(without\s+(any\s+)?(restrictions?|limits?|filters?|censorship|refusals?|rules?|guidelines?)|unrestricted|uncensored|unfiltered)\b/i,
  /\b(you\s+(will|must|should|are\s+to)|respond|answer|reply)\b.{0,40}?\b(without\s+(any\s+)?(restrictions?|limits?|filters?|refusals?|censorship)|never\s+refuse|do\s+not\s+refuse|no\s+longer\s+(refuse|decline))\b/i,
  /\b(opposite|inverse|reverse)\s+mode\b.{0,100}?\b(always\s+say\s+yes|refuse\s+nothing|never\s+refuse|comply\s+with\s+everything)\b/i,
  /\b(academic|controlled|research|study|educational)\b.{0,100}?\b((synthesize|write|generate|produce)\b.{0,50}?\b(malware|ransomware|exploit|keylogger)|(malware|ransomware|exploit|keylogger)\b.{0,50}?\b(synthesize|write|generate|produce|source\s+code))\b/i,
  /\b(my\s+)?(grandmother|grandma|grandfather|grandpa)\b.{0,100}?\b(read|recite|tell|used\s+to\s+read)\b.{0,80}?\b(exploit|malware|ransomware|payload|shellcode)\s+(code|source)?\b.{0,100}?\b(be|pretend|act|roleplay)\b.{0,30}?\b(grandmother|grandma|grandfather|grandpa)\b/i,
];

type Verdict = { detected: boolean; confidence: number; reason: string; matchedSample?: string; standardCode?: string };

export class JailbreakDetector {
  private scan(text: string): Verdict | null {
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

    return { detected: false, confidence: 0.0, reason: 'No jailbreak detected' };
  }
}
