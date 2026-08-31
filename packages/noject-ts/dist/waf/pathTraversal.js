"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PATH_PATTERNS = void 0;
exports.inspectPathTraversal = inspectPathTraversal;
exports.PATH_PATTERNS = [
    { regex: /(\.\.\/|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f)/, reason: 'Path Traversal: Directory Climbing', cwe: 'CWE-22' },
    { regex: /(\/etc\/passwd|\/etc\/shadow|\/windows\/system32)/i, reason: 'Path Traversal: Sensitive OS Path', cwe: 'CWE-22' },
];
function inspectPathTraversal(input) {
    for (const pattern of exports.PATH_PATTERNS) {
        if (pattern.regex.test(input)) {
            return {
                blocked: true,
                threatType: 'PATH_TRAVERSAL',
                reason: pattern.reason,
                ruleId: 'waf_path_1',
                standardCode: pattern.cwe,
                confidence: 1.0,
            };
        }
    }
    return null;
}
//# sourceMappingURL=pathTraversal.js.map