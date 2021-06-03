import { argon2id } from "hash-wasm";
import { deleteDB, openDB } from "idb";
import tweetnacl from "tweetnacl";

// https://diafygi.github.io/webcrypto-examples/
// https://github.com/willgm/web-crypto-tools/blob/master/src/web-crypto-tools.ts
// https://github.com/willgm/web-crypto-storage/blob/master/src/web-crypto-storage.ts
// https://github.com/willgm/web-crypto-storage/blob/master/demo/demo.js
// https://nodejs.org/api/crypto.html#crypto_crypto_verify_algorithm_data_key_signature_callback

const utf8StringToUint8Array = (data: string): Uint8Array =>
  new TextEncoder().encode(data);

const uint8ArrayToHexString = (data: Uint8Array): string =>
  Buffer.from(data).toString("hex");

const generateRandomValues = (length: number) =>
  window.crypto.getRandomValues(new Uint8Array(length));

const generateKeyPairFromPwAndSalt = async (
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
    outputType: "binary",
  });

  // use password hash as seed
  return tweetnacl.sign.keyPair.fromSeed(passwordHash);
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

  // deterministically generate key pair from password and salt
  const { publicKey } = await generateKeyPairFromPwAndSalt(password, salt);

  // TODO: send public key to the server
  // sendPublicKey(uint8ArrayToHexString(publicKey))

  await database.put(storeName, salt, "salt");
  return uint8ArrayToHexString(publicKey);
};

export const sign = async (password: string, data: string): Promise<string> => {
  const databaseName = "databaseName";
  const storeName = "storeName";

  const database = await openDB(databaseName, 1);
  const salt = await database.get(storeName, "salt");

  if (!salt) {
    throw new Error("Cannot retrieve salt");
  }

  const { secretKey } = await generateKeyPairFromPwAndSalt(password, salt);

  const signature = tweetnacl.sign.detached(
    utf8StringToUint8Array(data),
    secretKey
  );

  return uint8ArrayToHexString(signature);
};
