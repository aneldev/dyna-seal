"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateDynaSeal = exports.ESealValidationResolution = exports.createDynaSeal = void 0;
var dyna_crypt_1 = require("dyna-crypt");
var md5 = require("md5");
var createDynaSeal = function (_a) {
    var data = _a.data, createFingerprint = _a.createFingerprint, encryptionKey = _a.encryptionKey, expiresAt = _a.expiresAt;
    var fingerprint = md5(createFingerprint(data));
    var seal = (0, dyna_crypt_1.encrypt)({
        fingerprint: fingerprint,
        expiresAt: expiresAt,
    }, encryptionKey);
    return __assign(__assign({}, data), { seal: seal });
};
exports.createDynaSeal = createDynaSeal;
var ESealValidationResolution;
(function (ESealValidationResolution) {
    ESealValidationResolution["VALID"] = "VALID";
    ESealValidationResolution["NO_SEAL"] = "NO_SEAL";
    ESealValidationResolution["DECRYPTION_ERROR"] = "DECRYPTION_ERROR";
    ESealValidationResolution["DATA_MUTATED"] = "DATA_MUTATED";
    ESealValidationResolution["EXPIRED"] = "EXPIRED";
})(ESealValidationResolution = exports.ESealValidationResolution || (exports.ESealValidationResolution = {}));
var validateDynaSeal = function (_a) {
    var data = _a.data, createFingerprint = _a.createFingerprint, encryptionKey = _a.encryptionKey;
    var seal = data.seal;
    if (!seal)
        return {
            valid: false,
            resolution: ESealValidationResolution.NO_SEAL,
            expiresAt: -1,
        };
    var decrypted = (0, dyna_crypt_1.decrypt)(seal, encryptionKey) || null;
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
exports.validateDynaSeal = validateDynaSeal;
//# sourceMappingURL=dynaSeal.js.map