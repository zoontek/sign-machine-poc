// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type { NextApiRequest, NextApiResponse } from "next";
const crypto: typeof window["crypto"] = require("crypto").webcrypto;

const hexStringToArrayBuffer = (data: string): ArrayBuffer =>
  Uint8Array.from(Buffer.from(data, "hex"));

const stringToArrayBuffer = (data: string): ArrayBuffer =>
  new TextEncoder().encode(data);

export default async (req: NextApiRequest, res: NextApiResponse) => {
  const body = JSON.parse(req.body);

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    JSON.parse(body.publicKey),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );

  const isValid = await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    publicKey,
    hexStringToArrayBuffer(body.dataSignature),
    stringToArrayBuffer(body.dataToVerify)
  );

  res.status(200).json({ isValid });
};
