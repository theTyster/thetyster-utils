import { isBase64 } from "./index";
import { ENCRYPT_RETURNS, WRAPKEY_RETURNS } from "./constants";

interface CripToeOptions {
  /**
   * Elicits whether the function should out put a URL safe base64 string or a regular base64 string.
   * {@see encodeUrlSafeBase64}
   * {@see decodeSafeURL}
   ***/
  safeURL?: boolean;
  toBase64?: boolean;
}

/**
 * Used to determine the length of Uint8Array's for random values.
 **/
const intArrLength = 12;

export type EncryptReturnsSafeURL = {
  /**
   * Data encrypted to Base64 with special URL characters replaced.
   * Decode it back into Base64 with {@see CripToe.decodeUrlSafeBase64.}
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   **/
  readonly cipher: string;
  /**
   * This is the only time the key is returned anywhere.
   * It is always returned as an instance of CryptoKey.
   * If you don't want it to be available in scope, don't destructure it.
   **/
  readonly key: CryptoKey;
  /**
   * Init Vector converted to Base64 with special URL characters replaced.
   * Decode it back into Base64 with {@see CripToe.decodeUrlSafeBase64.}
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   * Init Vector does not need to be a secret.
   **/
  readonly initVector: string;
};

export type EncryptReturnsBase64 = {
  /**
   * Data encrypted and encoded to Base64.
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer}
   **/
  readonly cipher: string;
  /**
   * This is the only time the key is returned anywhere.
   * It is always returned as an instance of CryptoKey.
   * If you don't want it to be available in scope, don't destructure it.
   **/
  readonly key: CryptoKey;
  /**
   * Data encrypted and encoded to Base64.
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer}
   **/
  readonly initVector: string;
};

export type ExportedWraps = {
  /**
   * The key used to wrap the secret key. Returned as a JSON Web Key (JWK)
   * exported and stringified.
   *
   * JWK's are shaped something like this:
   *{
   *  "crv": "P-384",
   *  "d": "wouCtU7Nw4E8_7n5C1-xBjB4xqSb_liZhYMsy8MGgxUny6Q8NCoH9xSiviwLFfK_",
   *  "ext": true,
   *  "key_ops": ["sign"],
   *  "kty": "EC",
   *  "x": "SzrRXmyI8VWFJg1dPUNbFcc9jZvjZEfH7ulKI1UkXAltd7RGWrcfFxqyGPcwu6AQ",
   *  "y": "hHUag3OvDzEr0uUQND4PXHQTXP5IDGdYhJhL-WLKjnGjQAw0rNGy5V29-aV-yseW"
   *};
   **/
  readonly wrappingKey: string;
  /**
   * The secret key returned as encrypted by the wrapping key.
   **/
  readonly wrappedKey: ArrayBuffer | string;
};

export type ExportedWrapsSafeURL = {
  /**
   * Wrapping key converted to Base64 with special URL characters replaced.
   * Decode it back into Base64 with {@see CripToe.decodeUrlSafeBase64.}
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   **/
  readonly wrappingKey: string;
  /**
   * Secret key encrypted by wrapping key and converted to Base64 with special
   * URL characters replaced.
   * Decode it back into Base64 with {@see CripToe.decodeUrlSafeBase64.}
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   **/
  readonly wrappedKey: string;
};

export type ExportedWrapsBase64 = {
  /*nv$h{*
   * Wrapping key encoded to Base64.
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   **/
  readonly wrappingKey: string;
  /**
   * Secret Key encrypted and encoded to Base64.
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   **/
  readonly wrappedKey: string;
};

export type EncryptReturns = typeof ENCRYPT_RETURNS;
export type WrapKeyReturns = typeof WRAPKEY_RETURNS;

/** Provides Sha256 hashing and AES-GCM encryption and decryption of strings.*/
export default class CripToe {
  /**
   * The message originally provided to the instance for encryption.
   **/
  message: string;

  /**
   * The message originally provided to the instance encoded into a Uint8Array.
   **/
  encoded: Uint8Array;

  /**
   * @param message - String to be encrypted or hashed.
   **/
  constructor(message: string, password?: string, opts?: { silenceWarnings?: boolean }) {
    if (message.length > 1260 && !opts?.silenceWarnings ){
      console.warn(
        `WARNING: The message supplied to ${this.constructor.name} is possibly too long for a URL.\nTests show that messages longer than 1,260 characters may exceed the maximum recommended length for a URL, which is 2,084 characters.\nlength:\n${message.length}\nmessage:\n${message}`);
    }
    this.message = message;
    this.encoded = new TextEncoder().encode(message);

    // ENSURES THAT THE CIPHER IS ONLY GENERATED ONCE.
    this._cipher = undefined;

    // GENERATES THE ENCRYPTION KEY
    // This method uses a generator function to allow for the key to only be
    // generated when needed and only once. Additionally, this method is
    // scalable to allow for password based keys. If that is needed one day.
    this._cripKeyWalk = this.genCripKey(password ? password : undefined);
    this._cripKeyWalk.next().then((key) => {
      this._cripKey = key.value as undefined;
    });

    // ENSURES THAT THE WRAP KEY IS ONLY GENERATED ONCE.
    // Requires that salt be provided. Salt is not provided here. Although, you
    // can use 'Cripto.random()' to generate salt.
    this._wrappedKey = undefined;
  }

  /**
   * Hashes any string into a Sha256 hash. By default will hash the mesage initially provided to the constructor.
   **/
  async sha256(message?: string) {
    if (!message) message = this.message;
    const encoded = message ? new TextEncoder().encode(message) : this.encoded;
    return this.CRYP.digest("SHA-256", encoded).then((hash) => {
      const hashArray = Array.from(new Uint8Array(hash));
      const hashHex = hashArray
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
      return hashHex;
    });
  }

  /**
   * Encrypts the message into AES-GCM.
   * AES-GCM as opposed to AES-CBC or AES-CTR includes checks that the ciphertext has not been modified.
   **/
  async encrypt(options?: CripToeOptions) {
    if (!this._cripKey) {
      this._cripKey = await this._cripKeyWalk.next().then((key) => key.value);
    }
    if (!this._cipher) {
      const iv = this._iv;
      const key = this._cripKey!;
      const promisedCipher = await this.CRYP.encrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        key,
        this.encoded,
      );
      this._cipher = promisedCipher;
    }
    if (options?.safeURL) {
      return {
        cipher: CripToe.encodeUrlSafeBase64(this.encrypted),
        initVector: CripToe.encodeUrlSafeBase64(this.initVector),
        key: this._cripKey,
      } as const;
    } else if (options?.toBase64) {
      return {
        cipher: CripToe.arrayBufferToBase64(this._cipher),
        initVector: CripToe.arrayBufferToBase64(this._iv),
        key: this._cripKey,
      } as const;
    } else {
      return {
        cipher: this._cipher,
        initVector: this._iv,
        key: this._cripKey,
      } as const;
    }
  }

  /**Decrypts any AES-GCM encrypted data provided you have the necessary parameters.
   *
   * @param key - The Key used to initially encrypt. {@see CripToe.cripKey}
   * @param iv - The Initialization Vector or, nonce, used to salt the encryption. Provided as base64 string.
   * @param toDecrypt - The encrypted data to be decrypted. Provided as base64 string.
   **/
  async decrypt(
    cipher: ENCRYPT_RETURNS["cipher"],
    key: ENCRYPT_RETURNS["key"],
    initVector: ENCRYPT_RETURNS["initVector"],
    options?: CripToeOptions,
  ) {
    if (!(key instanceof CryptoKey))
      throw new Error(
        "You must provide a valid encryption key to decrypt. It should be an instance of CryptoKey.",
      );
    if (!(cipher instanceof ArrayBuffer || typeof cipher === "string"))
      throw new Error(
        "You must provide a valid encrypted message to decrypt. It should be an instance of ArrayBuffer or a string.",
      );

    if (typeof cipher === "string") {
      cipher = CripToe.base64ToArrayBuffer(cipher);
    }
    if (typeof initVector === "string") {
      initVector = new Uint8Array(CripToe.base64ToArrayBuffer(initVector));
    }

    const decrypted = await this.CRYP.decrypt(
      {
        name: "AES-GCM",
        iv: initVector,
      },
      key,
      cipher,
    );
    return new TextDecoder("utf-8").decode(decrypted);
  }

  async unwrapKey(wrappedKey: ArrayBuffer, wrappingKeyString: string) {
    const wrappingKey = await this._parseJWk(wrappingKeyString);
    const unWrappedKey = await this.CRYP.unwrapKey(
      "jwk",
      wrappedKey,
      wrappingKey,
      {
        name: "AES-KW",
      },
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["decrypt"],
    );

    this._wrappedKey = wrappedKey;
    this._cripKey = unWrappedKey;
    return true;
  }

  /**
   * Wraps the key in JWK (Json Web Key) format using AES-KW.
   * The benefit of AES-KW is that it doesn't require an Initialization Vector.
   * See: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey
   *
   * Even if this function is called multiple times the wrapped key will only be generated once.
   * Subsequent calls will simply return the originally wrapped key.
   *
   * @param wrappingKey (JWK) - The key used to wrap the secret key. If not provided, a new key will be generated.
   * @param opts - Options for exporting the wrapped key:
   * - export: boolean - Whether to export the wrapped key. Will return the wrapped key and the wrapping key in an Object:
   *   {
   *   wrappingKey: string,
   *   wrappedKey: ArrayBuffer
   *   }
   *  - safeURL: boolean - Whether to return the properties in the returned object as a special base64 encoding with special
   *  characters removed. To convert them back to standard base64 {@see CripToe.decodeUrlSafeBase64.}
   *  - toBase64: boolean - Whether to return the properties in the returned object as a standard base64 encoding. to convert
   *  them back to an ArrayBuffer @see CripToe.base64ToArrayBuffer.
   **/
  async wrapKey(
    opts: { export: boolean; safeURL?: boolean; toBase64?: boolean } = {
      export: false,
    },
    wrappingKeyJWK?: string,
  ) {
    // Check for encryption key.
    if (!this._cripKey) {
      this._cripKey = await this.genCripKey()
        .next()
        .then((key) => key.value);
    }
    if (this._wrappedKey) {
      return this._wrappedKey;
    }

    // Generate a key to wrap the key.
    // Intentionally not using the same method for generating a key as the one used to encrypt.
    let wrappingKey: CryptoKey;
    if (wrappingKeyJWK) {
      wrappingKey = await this._parseJWk(wrappingKeyJWK);
    } else {
      wrappingKey = await this.CRYP.generateKey(
        {
          name: "AES-KW",
          length: 256,
        },
        true,
        ["wrapKey", "unwrapKey"],
      );
    }

    const wrappedKey = await this.CRYP.wrapKey(
      "jwk",
      this._cripKey!,
      wrappingKey,
      {
        name: "AES-KW",
      },
    );

    this._wrappedKey = wrappedKey;

    const wrappingKeyJwk = await this.CRYP.exportKey("jwk", wrappingKey);
    const wrappingKeyString = JSON.stringify(wrappingKeyJwk);
    if (opts.export) {
      const exported = {
        wrappingKey: wrappingKeyString,
        wrappedKey: this._wrappedKey,
      } as ExportedWraps;
      if (opts.safeURL) {
        return {
          wrappingKey: CripToe.encodeUrlSafeBase64(wrappingKeyString),
          wrappedKey: CripToe.encodeUrlSafeBase64(this._wrappedKey),
        } as ExportedWrapsSafeURL;
      } else if (opts.toBase64) {
        return {
          wrappingKey: btoa(wrappingKeyString),
          wrappedKey: CripToe.arrayBufferToBase64(this._wrappedKey),
        } as ExportedWrapsBase64;
      } else {
        return exported as ExportedWraps;
      }
    } else {
      return this._wrappedKey;
    }
  }

  /**
   * The message encrypted into base64.
   **/
  get encrypted() {
    if (this._cipher instanceof ArrayBuffer)
      return CripToe.arrayBufferToBase64(this._cipher);
    else
      throw new Error(
        "Not encrypted yet. You must call the 'encrypt' method before calling this property.",
      );
  }

  /**
   * The Initial Vector, or nonce, used to salt the encryption.
   **/
  get initVector(): ENCRYPT_RETURNS["initVector"] {
    return CripToe.arrayBufferToBase64(this._iv.buffer);
  }

  /**
   * Converts an Array Buffer to a base64 string.
   **/
  static arrayBufferToBase64(buffer: ArrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  /**
   * Converts a base64 string into an Array Buffer
   **/
  static base64ToArrayBuffer(base64: string) {
    const normalizedbase64 = CripToe.decodeUrlSafeBase64(base64);
    const string = atob(normalizedbase64);
    const buffer = new ArrayBuffer(string.length);
    const bufferView = new Uint8Array(buffer);

    for (let i = 0; i < string.length; i++) {
      bufferView[i] = string.charCodeAt(i);
    }
    return buffer;
  }

  /**
   * Removes special characters from a base64 string for URL compatibility.
   * Removed characters include:
   * - '='
   * - '+'
   * - '/'
   *
   * {@see CripToe.encrypted}
   **/
  static encodeUrlSafeBase64(cipher: string | ArrayBuffer) {
    function stringCleaner(base64: string) {
      const urlSafe = encodeURIComponent(base64);
      return urlSafe;
    }
    if (cipher instanceof ArrayBuffer) {
      const base64 = CripToe.arrayBufferToBase64(cipher);
      return stringCleaner(base64);
    } else if (!isBase64(cipher)) {
      const base64 = btoa(cipher);
      return stringCleaner(base64);
    } else {
      return cipher;
    }
  }

  /**
   * Takes a base64 string that has been formatted with @link CripToe.encodeUrlSafeBase64
   **/
  static decodeUrlSafeBase64(urlSafe: string) {
    const base64 = decodeURIComponent(urlSafe);
    return base64;
  }

  private isNode =
    typeof process === "object" && process + "" === "[object process]";
  private _cipher: Exclude<ENCRYPT_RETURNS["cipher"], string>;
  private _cripKey: ENCRYPT_RETURNS["key"];
  private _cripKeyWalk: AsyncGenerator<undefined, CryptoKey, unknown>;
  private _wrappedKey: ArrayBuffer | undefined;

  /**Provides Node and browser compatibility for crypto.*/
  private CRYP = (() => {
    if (this.isNode) {
      const cryp = crypto.subtle;
      if (cryp instanceof SubtleCrypto) return cryp;
      else throw new Error("SubtleCrypto is not available.");
    } else if ("Not in Node") {
      const cryp = window.crypto.subtle;
      if (cryp instanceof SubtleCrypto) return cryp;
      else throw new Error("SubtleCrypto is not available.");
    } else throw new Error("You are not in a supported environment.");
  })();

  private async _parseJWk(JWK: string) {
    const wrappingKeyJwk = JSON.parse(JWK);
    return await this.CRYP.importKey(
      "jwk",
      wrappingKeyJwk,
      {
        name: "AES-KW",
      },
      true,
      ["unwrapKey"],
    );
  }

  get random() {
    if (this.isNode) {
      return crypto.getRandomValues(new Uint8Array(intArrLength));
    } else if ("Not in Node") {
      return window.crypto.getRandomValues(new Uint8Array(intArrLength));
    } else throw new Error("You are not in a supported environment.");
  }

  static random = () => {
    if (typeof process === "object" && process + "" === "[object process]") {
      return crypto.getRandomValues(new Uint8Array(intArrLength));
    } else if ("Not in Node") {
      return window.crypto.getRandomValues(new Uint8Array(intArrLength));
    } else throw new Error("You are not in a supported environment.");
  };

  /**
   * Intentional dupe of 'get random()'. To avoid accidentally reusing an initVector
   **/
  private _iv = (() => {
    if (this.isNode) {
      return crypto.getRandomValues(new Uint8Array(intArrLength));
    } else if ("Not in Node") {
      return window.crypto.getRandomValues(new Uint8Array(intArrLength));
    } else throw new Error("You are not in a supported environment.");
  })();

  /**The key used to encrypt and decrypt the message.**/
  private async *genCripKey(password?: string) {
    yield undefined;
    if (!password) {
      return await this.CRYP.generateKey(
        {
          name: "AES-GCM",
          length: 256,
        },
        true,
        ["encrypt", "decrypt"],
      );
    } else {
      return await this.CRYP.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey", "deriveBits"],
      );
    }
  }
}
