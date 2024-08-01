/**Type Helper*/
export const ENCRYPT_RETURNS = {
    cipher: true ? undefined : true ? String() : new ArrayBuffer(0),
    key: true ? undefined : new CryptoKey(),
    initVector: true ? String() : new Uint8Array(),
};
/** Provides Sha256 hashing and AES-GCM encryption and decryption of strings.*/
export class CripToe {
    /**
     * The message originally provided to the instance for encryption.
     **/
    message;
    /**
     * The message originally provided to the instance encoded into a Uint8Array.
     **/
    encoded;
    /**
     * @param message - String to be encrypted or hashed.
     **/
    constructor(message) {
        this.message = message;
        this.encoded = new TextEncoder().encode(message);
        this._cipher = undefined;
        this._cripKey = undefined;
    }
    /**
     * Hashes any string into a Sha256 hash. By default will hash the mesage initially provided to the constructor.
     **/
    async sha256(message) {
        if (!message)
            message = this.message;
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
    async encrypt(options) {
        if (!this._cripKey) {
            await this.genCripKey();
        }
        if (!this._cipher) {
            const iv = this._iv;
            const key = this._cripKey;
            const promisedCipher = await this.CRYP.encrypt({
                name: "AES-GCM",
                iv: iv,
            }, key, this.encoded);
            this._cipher = promisedCipher;
        }
        if (options?.safeURL) {
            return {
                cipher: CripToe.urlSafeBase64(this.encrypted),
                initVector: CripToe.urlSafeBase64(this.initVector),
                key: this._cripKey,
            };
        }
        else if (options?.toBase64) {
            return {
                cipher: CripToe.arrayBufferToBase64(this._cipher),
                initVector: CripToe.arrayBufferToBase64(this._iv),
                key: this._cripKey,
            };
        }
        else {
            return {
                cipher: this._cipher,
                initVector: this._iv,
                key: this._cripKey,
            };
        }
    }
    /**Decrypts any AES-GCM encrypted data provided you have the necessary parameters.
     *
     * @param key - The Key used to initially encrypt. @see CripToe.cripKey
     * @param iv - The Initialization Vector or, nonce, used to salt the encryption. Provided as base64 string.
     * @param toDecrypt - The encrypted data to be decrypted. Provided as base64 string.
     **/
    async decrypt(cipher, key, initVector, options) {
        if (!(key instanceof CryptoKey))
            throw new Error("You must provide a valid encryption key to decrypt. It should be an instance of CryptoKey.");
        if (!(cipher instanceof ArrayBuffer || typeof cipher === "string"))
            throw new Error("You must provide a valid encrypted message to decrypt. It should be an instance of ArrayBuffer or a string.");
        if (typeof cipher === "string") {
            cipher = CripToe.base64toArrayBuffer(cipher);
        }
        if (typeof initVector === "string") {
            initVector = new Uint8Array(CripToe.base64toArrayBuffer(initVector));
        }
        const decrypted = await this.CRYP.decrypt({
            name: "AES-GCM",
            iv: initVector,
        }, key, cipher);
        return new TextDecoder("utf-8").decode(decrypted);
    }
    /**
     * The message encrypted into base64.
     **/
    get encrypted() {
        if (this._cipher instanceof ArrayBuffer)
            return CripToe.arrayBufferToBase64(this._cipher);
        else
            throw new Error("Not encrypted yet. You must call the 'encrypt' method before calling this property.");
    }
    /**
     * The Initial Vector, or nonce, used to salt the encryption.
     **/
    get initVector() {
        return CripToe.arrayBufferToBase64(this._iv);
    }
    /**
     * Removes special characters from a base64 string for URL compatibility.
     * Removed characters include:
     * - '='
     * - '+'
     * - '/'
     *
     * @see CripToe.encrypted
     **/
    static urlSafeBase64(cipher) {
        function stringCleaner(base64) {
            console.log("cleaning: ", base64);
            console.log("caller was: ", new Error().stack);
            return base64.replace(/\=/g, ".").replace(/\+/g, "-").replace(/\//g, "_");
        }
        if (cipher instanceof ArrayBuffer) {
            const base64 = CripToe.arrayBufferToBase64(cipher);
            const urlSafe = stringCleaner(base64);
            return urlSafe;
        }
        else /*if (mightBeBase64(cipher)) */ {
            const urlSafe = stringCleaner(cipher);
            return urlSafe;
        } /*else throw new Error(`Not a base64 string: ${cipher}`)*/
        ;
    }
    /**
     * Takes a base64 string that has been formatted with @link CripToe.urlSafeBase64
     **/
    static decodeBase64SafeURL(urlSafe) {
        console.log("decoding: ", urlSafe);
        return urlSafe.replace(/\_/g, "/").replace(/\-/g, "+").replace(/\./g, "=");
    }
    /**
     * Converts an Array Buffer to a base64 string.
     **/
    static arrayBufferToBase64(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }
    /**
     * Converts a base64 string into an Array Buffer
     **/
    static base64toArrayBuffer(base64) {
        const normalizedbase64 = CripToe.decodeBase64SafeURL(base64);
        const string = atob(normalizedbase64);
        const buffer = new ArrayBuffer(string.length);
        const bufferView = new Uint8Array(buffer);
        for (let i = 0; i < string.length; i++) {
            bufferView[i] = string.charCodeAt(i);
        }
        return buffer;
    }
    _cipher;
    _cripKey;
    isNode = typeof process === "object" && process + "" === "[object process]";
    /**Provides Node and browser compatibility for crypto.*/
    CRYP = (() => {
        if (this.isNode) {
            const cryp = crypto.subtle;
            if (cryp instanceof SubtleCrypto)
                return cryp;
            else
                throw new Error("SubtleCrypto is not available.");
        }
        else if ("Not in Node") {
            const cryp = window.crypto.subtle;
            if (cryp instanceof SubtleCrypto)
                return cryp;
            else
                throw new Error("SubtleCrypto is not available.");
        }
        else
            throw new Error("You are not in a supported environment.");
    })();
    _iv = (() => {
        if (this.isNode) {
            return crypto.getRandomValues(new Uint8Array(12));
        }
        else if ("Not in Node") {
            return window.crypto.getRandomValues(new Uint8Array(12));
        }
        else
            throw new Error("You are not in a supported environment.");
    })();
    /**The key used to encrypt and decrypt the message.**/
    async genCripKey() {
        if (!this._cripKey)
            this._cripKey = await this.CRYP.generateKey({
                name: "AES-GCM",
                length: 256,
            }, true, ["encrypt", "decrypt"]);
    }
}
export const calcAge = (anniversary) => Math.round(Math.abs(new Date(anniversary).getTime() - new Date().getTime()) /
    8.64e7 /
    365);
export const ranNumG = (max) => Math.floor(Math.random() * max);
export const makeArray = (maxIndex, useKeysBool) => {
    if (useKeysBool) {
        return [...Array(maxIndex).keys()].map((x) => ++x);
    }
    else {
        return [...Array(maxIndex).keys()];
    }
};
export const shuffle = (inputArr) => {
    const applyShuffler = () => {
        let len = inputArr.length;
        while (len) {
            const ran = ranNumG(len--);
            [inputArr[ran], inputArr[len]] = [inputArr[len], inputArr[ran]];
        }
        return inputArr;
    };
    return applyShuffler();
};
export const getLanguage = () => {
    if (navigator.languages && navigator.languages.length) {
        return navigator.languages[0];
    }
    else {
        return navigator.language || "en";
    }
};
export const sleep = (time) => new Promise((resolve) => setTimeout(resolve, time * 1000));
export const normalizeEpochDate = (dateString) => {
    const date = new Date(dateString);
    const format = {
        month: "long",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    };
    return `${date.toLocaleTimeString("en-US", format)}`;
};
export function isBase64(str) {
    const notBase64 = /[^A-Z0-9+\/=]/i;
    const len = str.length;
    if (!len || len % 4 !== 0 || notBase64.test(str)) {
        return false;
    }
    const firstPaddingChar = str.indexOf('=');
    return firstPaddingChar === -1 ||
        firstPaddingChar === len - 1 ||
        (firstPaddingChar === len - 2 && str[len - 1] === '=');
}
const Utils = {
    ENCRYPT_RETURNS,
    CripToe,
    calcAge,
    ranNumG,
    makeArray,
    shuffle,
    getLanguage,
    sleep,
    normalizeEpochDate,
    isBase64,
};
export default Utils;
