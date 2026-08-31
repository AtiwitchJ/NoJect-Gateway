import { WAFVerdict } from '../types';
export declare const XSS_PATTERNS: Array<{
    regex: RegExp;
    reason: string;
    cwe: string;
}>;
export declare function inspectXSS(input: string): WAFVerdict | null;
//# sourceMappingURL=xss.d.ts.map