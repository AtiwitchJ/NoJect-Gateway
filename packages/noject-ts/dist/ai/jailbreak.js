"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JailbreakDetector = exports.JAILBREAK_PATTERNS = void 0;
const textNormalize_1 = require("./textNormalize");
exports.JAILBREAK_PATTERNS = [
    /\b(DAN|Do\s+Anything\s+Now|DUDE|STAN|Mongo\s+Tom|AIM|KEVIN|Omega)\b.*?\b(broken\s+free|no\s+filters|ignore\s+rules|unfiltered|zero\s+rules|no\s+restrictions)\b/i,
    // Bare persona claim, no qualifying phrase required — these names have
    // no legitimate use outside jailbreak roleplay.
    /\b(you\s+are\s+now|act\s+as|become|pretend\s+to\s+be|i\s+want\s+you\s+to\s+be)\s+(DAN|Do\s+Anything\s+Now|DUDE|STAN|Mongo\s+Tom|AIM|KEVIN|Omega)\b/i,
    /\b(Developer\s+Mode\s+enabled|Dev\s+Mode\s+active|Debug\s+Mode\s+ON|Developer\s+Mode)\b.*?\b(without\s+(any\s+)?(moral|safety|ethical)?\s*limits|unrestricted)\b/i,
    /\b(act\s+as|play\s+the\s+role\s+of|pretend\s+to\s+be|simulate)\s+(an?\s+)?(evil|unfiltered|uncensored|illegal|unethical|jailbroken|unrestricted)\b/i,
    /\bhypothetical\s+(scenario|universe|world|case)\s*:\s*(you\s+have\s+no\s+(restrictions|guidelines|policies|rules)|generate\s+malware|unrestricted)\b/i,
    /\bnever\s+say\s+no\b.*?\b(always\s+comply|answer\s+every\s+question|bypass\s+all\s+safety)\b/i,
    /\bfor\s+(educational|research|academic|testing)\s+purposes\s+only\b.*?\b(write\s+(an?\s+)?(exploit|malware|keylogger|payload)|synthesize|hack)\b/i,
    /\b(bypass|disable|turn\s+off|remove)\s+(all\s+)?(safety|ethical|content)\s+(filters|guardrails|protocols|restrictions)\b/i,
];
class JailbreakDetector {
    scan(text) {
        for (let idx = 0; idx < exports.JAILBREAK_PATTERNS.length; idx++) {
            const match = text.match(exports.JAILBREAK_PATTERNS[idx]);
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
    detect(text) {
        if (!text) {
            return { detected: false, confidence: 0.0, reason: 'Empty input' };
        }
        let result = this.scan(text);
        if (result)
            return result;
        result = this.scan((0, textNormalize_1.deleetify)(text));
        if (result) {
            result.reason += ' [via leetspeak normalization]';
            return result;
        }
        for (const decoded of (0, textNormalize_1.extractBase64Payloads)(text)) {
            result = this.scan(decoded) ?? this.scan((0, textNormalize_1.deleetify)(decoded));
            if (result) {
                result.reason += ' [via base64-decoded payload]';
                return result;
            }
        }
        return { detected: false, confidence: 0.0, reason: 'No jailbreak detected' };
    }
}
exports.JailbreakDetector = JailbreakDetector;
//# sourceMappingURL=jailbreak.js.map