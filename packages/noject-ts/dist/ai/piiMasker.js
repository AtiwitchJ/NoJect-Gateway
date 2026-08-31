"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PIIMasker = void 0;
class PIIMasker {
    patterns = [
        { type: 'THAI_NATIONAL_ID', regex: /\b\d{1}-?\d{4}-?\d{5}-?\d{2}-?\d{1}\b/g, replacement: '[THAI_ID]' },
        { type: 'PHONE_NUMBER', regex: /(\+66|0)[689]\d{1}[-\s]?\d{3}[-\s]?\d{4}\b/g, replacement: '[PHONE_NUMBER]' },
        { type: 'EMAIL', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replacement: '[EMAIL_REDACTED]' },
        { type: 'CREDIT_CARD', regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, replacement: '[CREDIT_CARD]' },
        { type: 'API_KEY', regex: /\b(sk-[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b/g, replacement: '[SECRET_KEY_REDACTED]' },
    ];
    mask(text) {
        if (!text) {
            return { maskedText: text, hasPii: false, entitiesFound: [], standardCode: 'ISO/IEC 42001 B.7.2 / OWASP LLM02:2025' };
        }
        let masked = text;
        const entitiesFound = [];
        for (const p of this.patterns) {
            if (p.regex.test(masked)) {
                entitiesFound.push(p.type);
                // Reset lastIndex because of /g flag
                p.regex.lastIndex = 0;
                masked = masked.replace(p.regex, p.replacement);
            }
        }
        return {
            maskedText: masked,
            hasPii: entitiesFound.length > 0,
            entitiesFound,
            standardCode: 'ISO/IEC 42001 B.7.2 / OWASP LLM02:2025',
        };
    }
}
exports.PIIMasker = PIIMasker;
//# sourceMappingURL=piiMasker.js.map