import { describe, test, expect } from "vitest";
import CripToe, {
  type ExportedWrapsSafeURL,
  type EncryptReturnsSafeURL,
} from "../src/CripToe";
import { isBase64 } from "../src/index";

async function setup() {
    const longTestMessage = `A really long test message that may be encrypted to test whether a really long message can remain under 2000 characters in length for a URL. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected.  This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected.This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected.This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryp`;
    const C = new CripToe(longTestMessage);
    const secret = (await C.encrypt({
      safeURL: true,
    })) as EncryptReturnsSafeURL;
    const { wrappingKey, wrappedKey } = (await C.wrapKey({
      export: true,
      safeURL: true,
    })) as ExportedWrapsSafeURL;
    return { C, secret, longTestMessage, wrappingKey, wrappedKey };
}

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
describe.each(variation)(
  "CripToe test: #%# safeURL: %s, toBase64: %s",
  async (safeURL, toBase64) => {
    const { C, secret, longTestMessage, wrappingKey, wrappedKey } = await setup();
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
        expect(isBase64(C.encrypted)).toBeTruthy();
      });

      test("CripToe should have an initVector property", () => {
        expect(C).toHaveProperty("initVector");
        expect(C.initVector).toBeTypeOf("string");
        expect(isBase64(C.initVector as string)).toBeTruthy();
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
      });
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
            !!isBase64(secret.initVector) ||
              !!isBase64(CripToe.decodeUrlSafeBase64(secret.initVector)),
            `${secret.initVector} was falsey. So, not a Uint8Array nor did it pass the base64 test.`,
          )
          .toBeTruthy();
        expect(typeof secret.cipher === "string").toBeTruthy();
        expect(
          isBase64(CripToe.decodeUrlSafeBase64(secret.cipher)),
        ).toBeTruthy();
      });

      test("Should create a wrapping key.", async () => {
        expect(wrappedKey, "Should be a string.").toBeTypeOf("string");
        expect(
          isBase64(wrappedKey),
          "Wrapped Key shold not be a base64 string",
        ).toBeFalsy();
        expect(
          isBase64(CripToe.decodeUrlSafeBase64(wrappedKey)),
          "SafeURL decoded wrapped Key shold be a base64 string",
        ).toBeTruthy();
        expect(wrappingKey, "Wrapping Key is not a string.").toBeTypeOf(
          "string",
        );
      });

      test("Should unwrap a key.", async () => {
        const C2 = new CripToe("Wrapping Test");
        const wrappedKeyB64 = CripToe.decodeUrlSafeBase64(wrappedKey);
        const wrappedKeyArrBuff = CripToe.base64ToArrayBuffer(wrappedKeyB64);
        const wrappingKeyJWK = Buffer.from(wrappingKey, "base64url").toString(
          "utf-8",
        );
        await C2.unwrapKey(wrappedKeyArrBuff, wrappingKeyJWK);
        //@ts-ignore Accessing a private property for testing.
        expect(C2._cripKey).toStrictEqual(secret.key);
        //@ts-ignore Accessing a private property for testing.
        expect(await C2.decrypt(secret.cipher, C2._cripKey, C.initVector)).toBe(
          longTestMessage,
        );
      });

      test("Should decrypt an encrypted string", async () => {
        const decrypted = await C.decrypt(
          secret.cipher,
          secret.key,
          secret.initVector,
        );
        expect(decrypted).toBeTruthy();
        expect(decrypted).toBe(longTestMessage);
      });
    });
  },
);

let iterations = 101;
while (iterations--) {
  describe(`URL Encoding test: ${iterations}`, async () => {
    const { C, secret, longTestMessage, wrappingKey, wrappedKey } = await setup();
    test("CripToe.encrypted getter should return a base64 string.", () => {
      expect(C.encrypted).toBeTypeOf("string");
      expect(isBase64(C.encrypted)).toBeTruthy();
    });

    test("Should return URL safe base64", () => {
      const testUrl = new URL(`https://example.com/${secret.cipher}`);
      testUrl.searchParams.set("k", wrappedKey);
      testUrl.searchParams.set("iv", secret.initVector);
      test;
      expect(testUrl).toBeDefined();
      expect(testUrl.toString(), "Cipher is not in the URL.").toContain(
        secret.cipher,
      );
      expect(
        testUrl.searchParams.get("k"),
        "Wrapped Key is not in the URL.",
      ).toContain(wrappedKey);
      expect(
        testUrl.searchParams.get("iv"),
        "Init Vector is not in the URL.",
      ).toContain(secret.initVector);
      expect
        .soft(testUrl.toString().length, "Resultant URL is too long.")
        .toBeLessThanOrEqual(2000);
    });

    test("Should decode safe URL back to base64", () => {
      expect(
        CripToe.decodeUrlSafeBase64(C.encrypted),
        "Nota  base64 string.",
      ).toMatch(CripToe.decodeUrlSafeBase64(secret.cipher));
    });
  });
}
