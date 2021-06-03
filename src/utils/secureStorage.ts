import base64ArrayBuffer from "base64-arraybuffer";
import { argon2id } from "hash-wasm";
import { deleteDB, openDB } from "idb";
import * as ed from "noble-ed25519";

// https://diafygi.github.io/webcrypto-examples/
// https://github.com/willgm/web-crypto-tools/blob/master/src/web-crypto-tools.ts
// https://github.com/willgm/web-crypto-storage/blob/master/src/web-crypto-storage.ts
// https://github.com/willgm/web-crypto-storage/blob/master/demo/demo.js
// https://nodejs.org/api/crypto.html#crypto_crypto_verify_algorithm_data_key_signature_callback

const arrayBufferToBase64 = base64ArrayBuffer.encode;
const base64ToArrayBuffer = base64ArrayBuffer.decode;

const decode = (data: ArrayBuffer) => new TextDecoder("utf-8").decode(data);
const encode = (data: string): Uint8Array => new TextEncoder().encode(data);

const generateHash = (data: string): Promise<ArrayBuffer> =>
  window.crypto.subtle.digest("SHA-256", encode(data));

const generateRandomValues = (length: number) =>
  window.crypto.getRandomValues(new Uint8Array(length));

const generatePrivateKeyFromPwAndSalt = async (
  password: string,
  salt: Uint8Array
) => {
  const passwordHash = await argon2id({
    password: password.normalize(),
    salt,
    parallelism: 1,
    iterations: 256,
    memorySize: 512,
    hashLength: 32,
    outputType: "hex",
  });

  // use password hash as private key
  return Buffer.from(passwordHash, "hex");
};

export const initSignMachine = async (password: string): Promise<string> => {
  const databaseName = "databaseName";
  const storeName = "storeName";

  // Delete the database if it already exists
  await deleteDB(databaseName);

  const database = await openDB(databaseName, 1, {
    upgrade: async (db) => {
      db.createObjectStore(storeName);
    },
  });

  // generate random salt
  const salt = generateRandomValues(16);

  // deterministically generate private key from pw and salt
  const privateKey = await generatePrivateKeyFromPwAndSalt(password, salt);

  // derive public key from it
  const publicKey = await ed.getPublicKey(privateKey);

  // TODO: send public key to the server
  // sendPublicKey(publicKey)

  await database.put(storeName, salt, "salt");

  return Buffer.from(publicKey).toString("hex");
};

export const sign = async (password: string, data: string): Promise<string> => {
  const databaseName = "databaseName";
  const storeName = "storeName";

  const database = await openDB(databaseName, 1);

  const salt = await database.get(storeName, "salt");

  if (!salt) {
    throw new Error("Cannot retrieve salt");
  }

  const privateKey = await generatePrivateKeyFromPwAndSalt(password, salt);

  const signature = await ed.sign(
    Buffer.from(data).toString("hex"),
    privateKey
  );

  // TODO: Protect from timing attack
  return signature;
};
