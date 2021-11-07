import {encrypt, decrypt} from "dyna-crypt";
import * as md5 from "md5";

export interface IDynaSeal {
  fingerprint: string;
  expiresAt: number;
}

export interface IDynaSealedData {
  seal: string;
}

export const createDynaSeal = <TData extends IDynaSealedData>(
  {
    data,
    createFingerprint,
    encryptionKey,
    expiresAt,
  }: {
    data: TData;
    createFingerprint: (data: TData) => string;
    encryptionKey: string;
    expiresAt: number;
  },
): TData => {
  const fingerprint = md5(createFingerprint(data));
  const seal = encrypt({
    fingerprint,
    expiresAt,
  } as IDynaSeal,
  encryptionKey,
  );
  return {
    ...data,
    seal,
  };
};

export enum ESealValidationResolution {
  VALID = "VALID",                        // Success
  NO_SEAL = "NO_SEAL",                    // Object hasn't `seal` property value to validate
  DECRYPTION_ERROR = "DECRYPTION_ERROR",  // Seal is encrypted with different key
  DATA_MUTATED = "DATA_MUTATED",          // The object is mutated! The fingerprints doesn't match.
  EXPIRED = "EXPIRED",                    // The data are expired, are no longer valid
}

export const validateDynaSeal = <TData extends IDynaSealedData>(
  {
    data,
    createFingerprint,
    encryptionKey,
  }: {
    data: TData;
    createFingerprint: (data: TData) => string;
    encryptionKey: string;
  },
): {
  valid: boolean;
  resolution: ESealValidationResolution;
  expiresAt: number;
} => {
  const seal = data.seal;
  if (!seal) return {
    valid: false,
    resolution: ESealValidationResolution.NO_SEAL,
    expiresAt: -1,
  };

  const decrypted: IDynaSeal | null = decrypt(seal, encryptionKey) || null;

  if (!decrypted) return {
    valid: false,
    resolution: ESealValidationResolution.DECRYPTION_ERROR,
    expiresAt: -1,
  };

  if (decrypted.expiresAt <= Date.now()) return {
    valid: false,
    resolution: ESealValidationResolution.EXPIRED,
    expiresAt: decrypted.expiresAt,
  };

  const fingerprint = md5(createFingerprint(data));
  if (decrypted.fingerprint !== fingerprint) return {
    valid: false,
    resolution: ESealValidationResolution.DATA_MUTATED,
    expiresAt: decrypted.expiresAt,
  };

  // At last, this is valid
  return {
    valid: true,
    resolution: ESealValidationResolution.VALID,
    expiresAt: decrypted.expiresAt,
  };
};
