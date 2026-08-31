"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.XSS_PATTERNS = void 0;
exports.inspectXSS = inspectXSS;
exports.XSS_PATTERNS = [
    { regex: /<\s*script\b[^>]*>/i, reason: 'XSS: Script Tag', cwe: 'CWE-79' },
    { regex: /\bon\w+\s*=\s*['"]?[^'">]+['"]?/i, reason: 'XSS: Inline Event Handler', cwe: 'CWE-79' },
    { regex: /javascript\s*:\s*/i, reason: 'XSS: Javascript Pseudo-protocol', cwe: 'CWE-79' },
    { regex: /<\s*(iframe|svg|embed|object|img)\b[^>]*\b(src|onload|onerror)\b/i, reason: 'XSS: Malicious Tag', cwe: 'CWE-79' },
];
function inspectXSS(input) {
    for (const pattern of exports.XSS_PATTERNS) {
        if (pattern.regex.test(input)) {
            return {
                blocked: true,
                threatType: 'XSS',
                reason: pattern.reason,
                ruleId: 'waf_xss_1',
                standardCode: pattern.cwe,
                confidence: 1.0,
            };
        }
    }
    return null;
}
//# sourceMappingURL=xss.js.map