export interface IDynaSeal {
    fingerprint: string;
    expiresAt: number;
}
export interface IDynaSealedData {
    seal: string;
}
export declare const createDynaSeal: <TData extends IDynaSealedData>({ data, createFingerprint, encryptionKey, expiresAt, }: {
    data: TData;
    createFingerprint: (data: TData) => string;
    encryptionKey: string;
    expiresAt: number;
}) => TData;
export declare enum ESealValidationResolution {
    VALID = "VALID",
    NO_SEAL = "NO_SEAL",
    DECRYPTION_ERROR = "DECRYPTION_ERROR",
    DATA_MUTATED = "DATA_MUTATED",
    EXPIRED = "EXPIRED"
}
export declare const validateDynaSeal: <TData extends IDynaSealedData>({ data, createFingerprint, encryptionKey, }: {
    data: TData;
    createFingerprint: (data: TData) => string;
    encryptionKey: string;
}) => {
    valid: boolean;
    resolution: ESealValidationResolution;
    expiresAt: number;
};
