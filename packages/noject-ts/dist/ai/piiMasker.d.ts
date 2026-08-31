export interface MaskPIIResult {
    maskedText: string;
    hasPii: boolean;
    entitiesFound: string[];
    standardCode: string;
}
export declare class PIIMasker {
    private patterns;
    mask(text: string): MaskPIIResult;
}
//# sourceMappingURL=piiMasker.d.ts.map