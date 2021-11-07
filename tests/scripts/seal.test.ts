import {
  createDynaSeal,
  validateDynaSeal,
  ESealValidationResolution,
} from "../../src";

describe('seal', () => {
  const product = {
    productId: '9824805246245',
    passenger: {
      firstName: 'John',
      lastName: 'Smith',
    },
    price: {
      value: 1200.34,
      currency: 'eur',
    },
    seal: '',
  };
  type IProduct = typeof product;

  const createFingerprint = (product: IProduct): string =>
    [
      product.productId,
      product.passenger.firstName,
      product.passenger.lastName,
    ].join('/');

  test('Valid seal', () => {
    const expiresAt = Date.now() + 20000;
    const sealedProduct = createDynaSeal<IProduct>({
      data: product,
      createFingerprint,
      encryptionKey: 'sssh-secret',
      expiresAt,
    });

    const validation = validateDynaSeal<IProduct>({
      data: sealedProduct,
      createFingerprint,
      encryptionKey: 'sssh-secret',
    });

    expect(validation.valid).toBeTruthy();
    expect(validation.expiresAt).toBe(expiresAt);
    expect(validation.expiresAt).toBeGreaterThan(Date.now());
  });

  test('Invalid, with NO_SEAL error', () => {
    const validation = validateDynaSeal<IProduct>({
      data: product,
      createFingerprint,
      encryptionKey: 'sssh-secret',
    });

    // Will be invalid, since the product object has not seal
    expect(validation.valid).toBeFalsy();
    expect(validation.resolution).toBe(ESealValidationResolution.NO_SEAL);
    expect(validation.expiresAt).toBe(-1);
  });

  test('Invalid, with DECRYPTION_ERROR error', () => {
    const expiresAt = Date.now() + 20000;
    const sealedProduct = createDynaSeal<IProduct>({
      data: product,
      createFingerprint,
      encryptionKey: 'sssh-secret',
      expiresAt,
    });

    const validation = validateDynaSeal<IProduct>({
      data: sealedProduct,
      createFingerprint,
      encryptionKey: 'sssh-secret--WRONG-KEY',
    });

    expect(validation.valid).toBeFalsy();
    expect(validation.resolution).toBe(ESealValidationResolution.DECRYPTION_ERROR);
    expect(validation.expiresAt).toBe(-1);
  });

  test('Invalid, with DATA_MUTATED error', () => {
    const expiresAt = Date.now() + 20000;
    const sealedProduct = createDynaSeal<IProduct>({
      data: product,
      createFingerprint,
      encryptionKey: 'sssh-secret',
      expiresAt,
    });

    const validation = validateDynaSeal<IProduct>({
      data: {
        ...sealedProduct,
        productId: 'Diff--product-id--43524',
      },
      createFingerprint,
      encryptionKey: 'sssh-secret',
    });

    expect(validation.valid).toBeFalsy();
    expect(validation.expiresAt).toBe(expiresAt);
    expect(validation.resolution).toBe(ESealValidationResolution.DATA_MUTATED);
  });

  test('Invalid, with EXPIRED error', () => {
    const expiresAt = Date.now() + -20000;
    const sealedProduct = createDynaSeal<IProduct>({
      data: product,
      createFingerprint,
      encryptionKey: 'sssh-secret',
      expiresAt,
    });

    const validation = validateDynaSeal<IProduct>({
      data: {
        ...sealedProduct,
      },
      createFingerprint,
      encryptionKey: 'sssh-secret',
    });

    expect(validation.valid).toBeFalsy();
    expect(validation.expiresAt).toBe(expiresAt);
    expect(validation.resolution).toBe(ESealValidationResolution.EXPIRED);
  });
});
