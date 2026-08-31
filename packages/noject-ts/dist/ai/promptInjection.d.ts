export declare const PROMPT_INJECTION_PATTERNS: RegExp[];
type Verdict = {
    detected: boolean;
    confidence: number;
    reason: string;
    matchedSample?: string;
    standardCode?: string;
};
export declare class PromptInjectionDetector {
    private scan;
    detect(text: string): Verdict;
}
export {};
//# sourceMappingURL=promptInjection.d.ts.map