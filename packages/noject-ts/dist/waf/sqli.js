"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SQLI_PATTERNS = void 0;
exports.inspectSQLi = inspectSQLi;
exports.SQLI_PATTERNS = [
    { regex: /\b(UNION\s+(ALL\s+)?SELECT|UNION\s+SELECT)\b/i, reason: 'SQLi: Union Select', cwe: 'CWE-89' },
    { regex: /(['"]\s*OR\s+['"]?1['"]?\s*=\s*['"]?1|['"]\s*OR\s+['"][a-zA-Z0-9]+['"]\s*=\s*['"][a-zA-Z0-9]+|OR\s+1\s*=\s*1\s*(--|#|\/\*))/i, reason: 'SQLi: Boolean True', cwe: 'CWE-89' },
    { regex: /;\s*(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|ALTER\s+TABLE|EXEC\s*\()/i, reason: 'SQLi: Stacked Query', cwe: 'CWE-89' },
    { regex: /\b(SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(\s*\d+|WAITFOR\s+DELAY\s+['"]\d+)/i, reason: 'SQLi: Time-based Blind', cwe: 'CWE-89' },
    { regex: /['"]\s*(--|#|\/\*)/i, reason: 'SQLi: Comment Auth Bypass', cwe: 'CWE-89' },
];
function inspectSQLi(input) {
    for (const pattern of exports.SQLI_PATTERNS) {
        if (pattern.regex.test(input)) {
            return {
                blocked: true,
                threatType: 'SQL_INJECTION',
                reason: pattern.reason,
                ruleId: 'waf_sqli_1',
                standardCode: pattern.cwe,
                confidence: 1.0,
            };
        }
    }
    return null;
}
//# sourceMappingURL=sqli.js.map