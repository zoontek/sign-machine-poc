// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type { NextApiRequest, NextApiResponse } from "next";
import * as srpServer from "../../../custom-srp/server";
import {
  base64ToArrayBuffer,
  encode,
  extractProof,
} from "../../../utils/common";
import { getLoginData, getRegisterData } from "../db";
const crypto: typeof window["crypto"] = require("crypto").webcrypto;

type LoginVerifyBody = {
  data: string; // data contains the proof
  signature: string;
};

export default async (req: NextApiRequest, res: NextApiResponse) => {
  const body: LoginVerifyBody = JSON.parse(req.body);

  const { proof } = extractProof(body.data);

  // login data must be stored somewhere permanently, to be able to prove
  // the signature at any time
  const { clientPublicKey, serverSecretKey } = getLoginData();

  const { salt, publicKey, verifier } = getRegisterData();

  let serverProof = null;
  try {
    // throws if the client proof is wrong
    const serverSession = srpServer.deriveSession(
      serverSecretKey,
      clientPublicKey,
      salt,
      "",
      verifier,
      proof
    );
    serverProof = serverSession.proof;
  } catch (err) {
    console.log(err);
  }

  const importedPublicKey = await crypto.subtle.importKey(
    "jwk",
    publicKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );

  const signatureIsValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    importedPublicKey,
    base64ToArrayBuffer(body.signature),
    encode(body.data)
  );

  res.status(200).json({ signatureIsValid, serverProof });
};
