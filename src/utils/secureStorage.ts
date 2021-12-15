import { deleteDB, openDB } from "idb";

// https://diafygi.github.io/webcrypto-examples/
// https://github.com/willgm/web-crypto-tools/blob/master/src/web-crypto-tools.ts
// https://github.com/willgm/web-crypto-storage/blob/master/src/web-crypto-storage.ts
// https://github.com/willgm/web-crypto-storage/blob/master/demo/demo.js
// https://nodejs.org/api/crypto.html#crypto_crypto_verify_algorithm_data_key_signature_callback

const stringToArrayBuffer = (data: string): ArrayBuffer =>
  new TextEncoder().encode(data);

const arrayBufferToHexString = (data: ArrayBuffer): string =>
  Buffer.from(data).toString("hex");

const generateRandomValues = (length: number) =>
  window.crypto.getRandomValues(new Uint8Array(length));

export const initSignMachine = async (
  password: string
): Promise<JsonWebKey> => {
  const databaseName = "databaseName";
  const storeName = "storeName";

  // Delete the database if it already exists
  await deleteDB(databaseName);

  const database = await openDB(databaseName, 1, {
    upgrade: async (db) => {
      db.createObjectStore(storeName);
    },
  });

  const ecdsaKey = await window.crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"]
  );

  if (!ecdsaKey.privateKey || !ecdsaKey.publicKey) {
    throw new Error("ECDSA keys are not exported");
  }

  const pbkdf2Key = await window.crypto.subtle.importKey(
    "raw",
    stringToArrayBuffer(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  // https://github.com/diafygi/webcrypto-examples/#pbkdf2---derivekey
  const salt = generateRandomValues(16);

  const aesGcmKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: 310000, // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2,
    },
    pbkdf2Key,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["wrapKey"]
  );

  // https://github.com/diafygi/webcrypto-examples/#aes-gcm---wrapkey
  const wrappedPrivateKeyNonce = generateRandomValues(16);

  const [wrappedPrivateKey, publicKey] = await Promise.all([
    window.crypto.subtle.wrapKey("pkcs8", ecdsaKey.privateKey, aesGcmKey, {
      name: "AES-GCM",
      iv: wrappedPrivateKeyNonce,
    }),
    window.crypto.subtle.exportKey("jwk", ecdsaKey.publicKey),
  ]);

  await Promise.all([
    database.put(storeName, salt, "salt"),
    database.put(storeName, wrappedPrivateKey, "wrappedPrivateKey"),
    database.put(storeName, wrappedPrivateKeyNonce, "wrappedPrivateKey-nonce"),
  ]);

  return publicKey;
};

export const sign = async (password: string, data: string): Promise<string> => {
  const databaseName = "databaseName";
  const storeName = "storeName";

  const database = await openDB(databaseName, 1);

  const [salt, wrappedPrivateKey, wrappedPrivateKeyNonce] = await Promise.all([
    database.get(storeName, "salt"),
    database.get(storeName, "wrappedPrivateKey"),
    database.get(storeName, "wrappedPrivateKey-nonce"),
  ]);

  if (!salt || !wrappedPrivateKey || !wrappedPrivateKeyNonce) {
    throw new Error("Cannot retrieve data");
  }

  const pbkdf2Key = await window.crypto.subtle.importKey(
    "raw",
    stringToArrayBuffer(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const aesGcmKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: 310000, // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2,
    },
    pbkdf2Key,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["unwrapKey"]
  );

  try {
    const privateKey = await window.crypto.subtle.unwrapKey(
      "pkcs8",
      wrappedPrivateKey,
      aesGcmKey,
      {
        name: "AES-GCM",
        iv: wrappedPrivateKeyNonce,
      },
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["sign"]
    );

    const signature = await window.crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      privateKey,
      stringToArrayBuffer(data)
    );

    // TODO: Protect from timing attack
    return arrayBufferToHexString(signature);
  } catch (error) {
    // TODO: Return data (garbage in : garbage out)
    throw new Error("Integrity / Authenticity check failed!");
  }
};
