import { WAFVerdict } from '../types';
export declare const SQLI_PATTERNS: Array<{
    regex: RegExp;
    reason: string;
    cwe: string;
}>;
export declare function inspectSQLi(input: string): WAFVerdict | null;
//# sourceMappingURL=sqli.d.ts.map