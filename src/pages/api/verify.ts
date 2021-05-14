// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import base64ArrayBuffer from "base64-arraybuffer";
import type { NextApiRequest, NextApiResponse } from "next";
const crypto = require("crypto").webcrypto;

const arrayBufferToBase64 = base64ArrayBuffer.encode;
const base64ToArrayBuffer = base64ArrayBuffer.decode;

const decode = (data: ArrayBuffer) => new TextDecoder("utf-8").decode(data);
const encode = (data: string): Uint8Array => new TextEncoder().encode(data);

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
    base64ToArrayBuffer(body.dataSignature),
    encode(body.dataToVerify)
  );

  res.status(200).json({ isValid });
};
