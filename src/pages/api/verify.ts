// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import base64ArrayBuffer from "base64-arraybuffer";
import { eddsa as Eddsa } from "elliptic";
import type { NextApiRequest, NextApiResponse } from "next";

const arrayBufferToBase64 = base64ArrayBuffer.encode;
const base64ToArrayBuffer = base64ArrayBuffer.decode;

const decode = (data: ArrayBuffer) => new TextDecoder("utf-8").decode(data);
const encode = (data: string): Uint8Array => new TextEncoder().encode(data);

const eddsa = new Eddsa("ed25519");

export default async (req: NextApiRequest, res: NextApiResponse) => {
  const body = JSON.parse(req.body);

  const publicKey = eddsa.keyFromPublic(body.publicKey);

  const isValid = publicKey.verify(body.dataToVerify, body.dataSignature);

  res.status(200).json({ isValid });
};
