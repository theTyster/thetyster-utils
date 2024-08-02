import { describe, test, expect } from "vitest";
import Utils, {
  CripToe,
  type ExportedWraps,
  calcAge,
  ranNumG,
  makeArray,
  shuffle,
  getLanguage,
  sleep,
  normalizeEpochDate,
} from "../src/index";

describe("Utils", () => {
  test("should be defined", () => {
    const u = Utils;
    expect(u).toBeDefined();
    expect(u.ENCRYPT_RETURNS).toBeDefined();
    expect(u.CripToe).toBeDefined();
    expect(u.calcAge).toBeDefined();
    expect(u.ranNumG).toBeDefined();
    expect(u.makeArray).toBeDefined();
    expect(u.shuffle).toBeDefined();
    expect(u.getLanguage).toBeDefined();
    expect(u.sleep).toBeDefined();
    expect(u.normalizeEpochDate).toBeDefined();
    expect(u.isBase64).toBeDefined();
  });

  //prettier-ignore
  // {
  const variation = [
  /**safeURL    toBase64*/
    [true,      true],
    [false,     false],
    [true,      false],
    [false,     true],
    [undefined, undefined],
    [undefined, true],
    [undefined, false],
    [true,      undefined],
    [false,     undefined],
  ]
  // }
  describe.each(variation)("CripToe", async (safeURL, toBase64) => {
    const C = new CripToe("Test Message");
    const secret = await C.encrypt({ safeURL, toBase64 });
    const { wrappingKey, wrappedKey } = await C.wrapKey({ export: true }) as ExportedWraps;
    class CripToeTest extends CripToe {
      constructor() {
        super("Inner Class Tests");
        this.encrypted; // Must be called inside this mock class to avoid an error in the test.
      }
    }

    describe("Properties", () => {
      test("CripToe should have an encrypted property", () => {
        expect(C).toHaveProperty("encrypted");
        expect(typeof C.encrypted).toMatch(/string|ArrayBuffer/);
        expect(Utils.isBase64(C.encrypted)).toBeTruthy();
      });

      test("CripToe should have an initVector property", () => {
        expect(C).toHaveProperty("initVector");
        expect(C.initVector).toBeTypeOf("string");
        expect(Utils.isBase64(C.initVector as string)).toBeTruthy();
      });

      test("CripToe should not have a key property initially.", () => {
        expect(C).not.toHaveProperty("key");
      });

      test("CripToe should have a cipher property initially.", () => {
        expect(C).not.toHaveProperty("cipher");
      });

      test("'random' should always be different.", () => {
        expect(C.random).not.toBe(C.random);
        expect(C.random).not.toMatchObject(C.random);
        expect(C.random).not.toEqual(C.random);
        expect(C.random).not.toStrictEqual(C.random);
        expect(CripToe.random()).not.toBe(CripToe.random());
        expect(CripToe.random()).not.toMatchObject(CripToe.random());
        expect(CripToe.random()).not.toEqual(CripToe.random());
        expect(CripToe.random()).not.toStrictEqual(CripToe.random());
      })
    });

    describe.shuffle("Methods", () => {
      test("Sha256 should return a hashed string", async () => {
        expect(await C.sha256()).toMatchSnapshot();
      });

      test("encrypt() should encrypt a string", async () => {
        expect(() => new CripToeTest()).toThrowError(
          "Not encrypted yet. You must call the 'encrypt' method before calling this property.",
        );
        expect(secret.key).toBeInstanceOf(CryptoKey);
        expect
          .soft(
            !!(secret.initVector instanceof Uint8Array) ||
              !!Utils.isBase64(secret.initVector) ||
              !!Utils.isBase64(CripToe.decodeBase64SafeURL(secret.initVector)),
            `${secret.initVector} was falsey. So, not a Uint8Array nor did it pass the base64 test.`,
          )
          .toBeTruthy();
      });

      test("Should create a wrapping key.", async () => {
        expect(wrappedKey, "Should be a JWK key.").toBeInstanceOf(ArrayBuffer);
        expect(wrappedKey).not.toBe(secret.key);
        expect(wrappedKey).toBe(await C.wrapKey());
        expect(wrappingKey).toBeTypeOf('string');
        expect(wrappingKey).not.toBe(secret.key);
      })

      test("Should unwrap a key.", async () => {
        const C2 = new CripToe("Wrapping Test");
        await C2.unwrapKey(wrappedKey, wrappingKey);
        //@ts-ignore Accessing a private property for testing.
        expect(C2._cripKey).toStrictEqual(secret.key);
        //@ts-ignore Accessing a private property for testing.
        expect(await C2.decrypt(secret.cipher, C2._cripKey, C.initVector )).toBe("Test Message");
      });

      describe("URL encoding", () => {
        test("CripToe.encrypted getter should return a base64 string.", () => {
          expect(C.encrypted).toBeTypeOf("string");
          expect(Utils.isBase64(C.encrypted)).toBeTruthy();
        });

        test("Should return URL safe base64", () => {
          expect(
            new URL(
              `https://example.com/${CripToe.urlSafeBase64(C.encrypted)}/${CripToe.urlSafeBase64(C.initVector)}`,
            ),
          ).toBeInstanceOf(URL);
        });

        test("Should decode safe URL back to base64", () => {
          expect(
            CripToe.decodeBase64SafeURL(CripToe.urlSafeBase64(C.encrypted)),
          ).toMatch(CripToe.arrayBufferToBase64(secret.cipher as ArrayBuffer));
        });
      });

      test("Should decrypt an encrypted string", async () => {
        const decrypted = await C.decrypt(
          secret.cipher,
          secret.key,
          secret.initVector,
        );
        expect(decrypted).toBeTruthy();
        expect(decrypted).toBe("Test Message");
      });
    });
  });

  describe("calcAge", () => {
    test("should return the correct age", () => {
      expect(calcAge("1990-09-01")).toBe(34);
    });
  });

  describe("ranNumG", () => {
    test("should return a random number", () => {
      expect(ranNumG(10)).toBeGreaterThanOrEqual(0);
      expect(ranNumG(10)).toBeLessThanOrEqual(10);
    });
  });

  describe("makeArray", () => {
    test("should return an array of numbers", () => {
      expect(makeArray(6)).toMatchInlineSnapshot([0, 1, 2, 3, 4, 5]);
    });
  });

  describe("shuffle", () => {
    test("should shuffle an array", () => {
      expect(shuffle([1, 2, 3, 4, 5])).not.toEqual([1, 2, 3, 4, 5]);
    });
  });

  describe.todo("getLanguage", () => {
    test("should return the correct language", () => {
      expect(getLanguage()).toBe("en");
    });
  });

  describe("sleep", () => {
    test("should resolve after a certain amount of time", async () => {
      const start = Date.now();
      await sleep(0.01);
      const end = Date.now();
      expect(end - start).toBeGreaterThanOrEqual(10);
    });
  });

  describe("normalizeEpochDate", () => {
    test("should return a formatted date string", () => {
      expect(normalizeEpochDate("2012-12-12 23:59:00")).toBe(
        "December 12, 2012 at 11:59 PM",
      );
    });
  });
});

describe("mightBeBase65", () => {
  test("should return true if the string might be base64", () => {
    expect.soft(Utils.isBase64("dGVzdA7r5f6gDgh4bxao+l==")).toBe(true);
    expect.soft(Utils.isBase64("7r5f6grMv4hDgh4tosp/lg==")).toBe(true);
    expect.soft(Utils.isBase64("hsFMy8Hk604LHf0En+e/sA==")).toBe(true);
    expect.soft(Utils.isBase64("yR6au1Ag/NysRMznd9x7mQ==")).toBe(true);
    expect.soft(Utils.isBase64("Xzs92E7PY0eGbY7LrxV6uQ==")).toBe(true);
    expect.soft(Utils.isBase64("k8t3lvtKjWw57VgzZvKDnA==")).toBe(true);
    expect.soft(Utils.isBase64("IApEOKTa6dc45/4zBnEz7g==")).toBe(true);
    expect.soft(Utils.isBase64("Q4xj6s3GtMvM8zX2z6g9GQ==")).toBe(true);
  });

  test("should return false if the string is not base64", () => {
    expect(Utils.isBase64("----")).toBe(false);
    expect(Utils.isBase64("____")).toBe(false);
    expect(Utils.isBase64("....")).toBe(false);
  });
});
