import { WAFVerdict } from '../types';
export declare const PATH_PATTERNS: Array<{
    regex: RegExp;
    reason: string;
    cwe: string;
}>;
export declare function inspectPathTraversal(input: string): WAFVerdict | null;
//# sourceMappingURL=pathTraversal.d.ts.map