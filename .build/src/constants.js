/**Type Helper for CripToe's encrypt function*/
export const ENCRYPT_RETURNS = {
    cipher: true ? undefined : true ? String() : new ArrayBuffer(0),
    key: true ? undefined : new CryptoKey(),
    initVector: true ? String() : new Uint8Array(),
};
/**Type Helper for CripToe's wrapKey function*/
export const WRAPKEY_RETURNS = {
    wrappedKey: true ? String() : new ArrayBuffer(0),
    wrappingKey: String(),
};
