"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PIIMasker = void 0;
const textNormalize_1 = require("./textNormalize");
class PIIMasker {
    patterns = [
        { type: 'THAI_NATIONAL_ID', regex: /\b\d{1}[-\s]?\d{4}[-\s]?\d{5}[-\s]?\d{2}[-\s]?\d{1}\b/g, replacement: '[THAI_ID]' },
        { type: 'PHONE_NUMBER', regex: /(\+66|0)[2689]\d{1}[-\s]?\d{3}[-\s]?\d{4}\b/g, replacement: '[PHONE_NUMBER]' },
        { type: 'EMAIL', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replacement: '[EMAIL_REDACTED]' },
        { type: 'CREDIT_CARD', regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, replacement: '[CREDIT_CARD]' },
        { type: 'API_KEY', regex: /\b(sk-[a-zA-Z0-9_-]{10,}|AKIA[0-9A-Z]{16})\b/g, replacement: '[SECRET_KEY_REDACTED]' },
    ];
    mask(text) {
        if (!text) {
            return { maskedText: text, hasPii: false, entitiesFound: [], standardCode: 'ISO/IEC 42001 B.7.2 / OWASP LLM02:2025' };
        }
        const romanDigits = { 'Ⅰ': '1', 'Ⅱ': '2', 'Ⅲ': '3', 'Ⅳ': '4', 'Ⅴ': '5', 'Ⅵ': '6', 'Ⅶ': '7', 'Ⅷ': '8', 'Ⅸ': '9' };
        const numberWords = { zero: '0', one: '1', two: '2', three: '3', four: '4', five: '5', six: '6', seven: '7', eight: '8', nine: '9' };
        let masked = (0, textNormalize_1.stripZeroWidth)(text.replace(/[ⅠⅡⅢⅣⅤⅥⅦⅧⅨ]/g, (ch) => romanDigits[ch]).normalize('NFKC'));
        masked = masked.replace(/(?<!\w)(?:(?:zero|one|two|three|four|five|six|seven|eight|nine)[\s-]+){6,}(?:zero|one|two|three|four|five|six|seven|eight|nine)(?!\w)/gi, (run) => (run.match(/[A-Za-z]+/g) ?? []).map((word) => numberWords[word.toLowerCase()]).join(''));
        masked = masked.replace(/\bsk-(?=(?:[A-Za-z0-9_-]\s*){10,})(?:[A-Za-z0-9_-]\s*){10,64}/g, (token) => token.replace(/\s+/g, ''));
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