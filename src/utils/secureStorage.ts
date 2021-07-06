import { argon2id } from "hash-wasm";
import { deleteDB, openDB } from "idb";
import * as srpClient from "../custom-srp/client";
import { addProof, arrayBufferToBase64, encodeUtf8 } from "./common";

// https://diafygi.github.io/webcrypto-examples/
// https://github.com/willgm/web-crypto-tools/blob/master/src/web-crypto-tools.ts
// https://github.com/willgm/web-crypto-storage/blob/master/src/web-crypto-storage.ts
// https://github.com/willgm/web-crypto-storage/blob/master/demo/demo.js
// https://nodejs.org/api/crypto.html#crypto_crypto_verify_algorithm_data_key_signature_callback

const derivePrivateKey = async (password: string, salt: string) => {
  return argon2id({
    password: password.normalize(),
    salt,
    parallelism: 1,
    iterations: 256,
    memorySize: 512,
    hashLength: 32,
    outputType: "hex",
  });
};

export const registerSignMachine = async (
  password: string
): Promise<{ salt: string; verifier: string; publicKey: JsonWebKey }> => {
  const databaseName = "databaseName";
  const storeName = "storeName";

  // Delete the database if it already exists
  await deleteDB(databaseName);

  const database = await openDB(databaseName, 1, {
    upgrade: async (db) => {
      db.createObjectStore(storeName);
    },
  });

  const salt = srpClient.generateSalt();
  const srpPrivateKey = await derivePrivateKey(password.normalize(), salt);
  const verifier = srpClient.deriveVerifier(srpPrivateKey);

  const ecdsaKey = await window.crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"]
  );

  await database.put(storeName, ecdsaKey.privateKey, "privateKey");

  const publicKey = await window.crypto.subtle.exportKey(
    "jwk",
    ecdsaKey.publicKey
  );

  await fetch("/api/register", {
    method: "POST",
    body: JSON.stringify({
      salt,
      verifier,
      publicKey,
    }),
  });

  return { salt, verifier, publicKey };
};

export const sign = async (
  password: string,
  data: string
): Promise<{
  dataWithProof: string;
  signatureBase64: string;
  srpProof: string;
  srpPublicKey: string;
}> => {
  const databaseName = "databaseName";
  const storeName = "storeName";
  const username = "";

  const database = await openDB(databaseName, 1);

  const privateKey = await database.get(storeName, "privateKey");

  if (!privateKey) {
    throw new Error("Cannot retrieve private key from db");
  }

  const clientEphemeral = srpClient.generateEphemeral();

  const res = await fetch("/api/login/start", {
    method: "POST",
    body: JSON.stringify({
      username,
      clientPublicKey: clientEphemeral.public,
    }),
  });

  const { salt, serverPublicKey } = await res.json();

  const srpPrivateKey = await derivePrivateKey(password.normalize(), salt);

  const clientSession = await srpClient.deriveSession(
    clientEphemeral.secret,
    serverPublicKey,
    salt,
    username,
    srpPrivateKey
  );

  const dataToSign = addProof(data, clientSession.proof);

  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    privateKey,
    encodeUtf8(dataToSign)
  );

  // TODO: Protect from timing attack
  const signatureBase64 = arrayBufferToBase64(signatureBuffer);

  return {
    signatureBase64,
    dataWithProof: dataToSign,
    srpProof: clientSession.proof,
    srpPublicKey: clientEphemeral.public,
  };
};

export const verifySignature = async (
  dataWithProof: string,
  signatureBase64: string
): Promise<{ signatureIsValid: boolean; serverProof: string | null }> => {
  const verifyRes = await fetch("/api/login/verify", {
    method: "POST",
    body: JSON.stringify({
      data: dataWithProof,
      signature: signatureBase64,
    }),
  });

  const verifyResBody = await verifyRes.json();

  return verifyResBody;
};
