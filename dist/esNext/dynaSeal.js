var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
import { encrypt, decrypt } from "dyna-crypt";
import * as md5 from "md5";
export var createDynaSeal = function (_a) {
    var data = _a.data, createFingerprint = _a.createFingerprint, encryptionKey = _a.encryptionKey, expiresAt = _a.expiresAt;
    var fingerprint = md5(createFingerprint(data));
    var seal = encrypt({
        fingerprint: fingerprint,
        expiresAt: expiresAt,
    }, encryptionKey);
    return __assign(__assign({}, data), { seal: seal });
};
export var ESealValidationResolution;
(function (ESealValidationResolution) {
    ESealValidationResolution["VALID"] = "VALID";
    ESealValidationResolution["NO_SEAL"] = "NO_SEAL";
    ESealValidationResolution["DECRYPTION_ERROR"] = "DECRYPTION_ERROR";
    ESealValidationResolution["DATA_MUTATED"] = "DATA_MUTATED";
    ESealValidationResolution["EXPIRED"] = "EXPIRED";
})(ESealValidationResolution || (ESealValidationResolution = {}));
export var validateDynaSeal = function (_a) {
    var data = _a.data, createFingerprint = _a.createFingerprint, encryptionKey = _a.encryptionKey;
    var seal = data.seal;
    if (!seal)
        return {
            valid: false,
            resolution: ESealValidationResolution.NO_SEAL,
            expiresAt: -1,
        };
    var decrypted = decrypt(seal, encryptionKey) || null;
    if (!decrypted)
        return {
            valid: false,
            resolution: ESealValidationResolution.DECRYPTION_ERROR,
            expiresAt: -1,
        };
    if (decrypted.expiresAt <= Date.now())
        return {
            valid: false,
            resolution: ESealValidationResolution.EXPIRED,
            expiresAt: decrypted.expiresAt,
        };
    var fingerprint = md5(createFingerprint(data));
    if (decrypted.fingerprint !== fingerprint)
        return {
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
//# sourceMappingURL=dynaSeal.js.map