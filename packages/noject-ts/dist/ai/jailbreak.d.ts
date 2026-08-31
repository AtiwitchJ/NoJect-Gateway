export declare const JAILBREAK_PATTERNS: RegExp[];
type Verdict = {
    detected: boolean;
    confidence: number;
    reason: string;
    matchedSample?: string;
    standardCode?: string;
};
export declare class JailbreakDetector {
    private scan;
    detect(text: string): Verdict;
}
export {};
//# sourceMappingURL=jailbreak.d.ts.map