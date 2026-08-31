import { WAFVerdict } from '../types';
export declare const CMD_PATTERNS: Array<{
    regex: RegExp;
    reason: string;
    cwe: string;
}>;
export declare function inspectCMD(input: string): WAFVerdict | null;
//# sourceMappingURL=cmd.d.ts.map