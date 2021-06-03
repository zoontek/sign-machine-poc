// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import base64ArrayBuffer from "base64-arraybuffer";
import type { NextApiRequest, NextApiResponse } from "next";
import * as ed from "noble-ed25519";

const arrayBufferToBase64 = base64ArrayBuffer.encode;
const base64ToArrayBuffer = base64ArrayBuffer.decode;

const decode = (data: ArrayBuffer) => new TextDecoder("utf-8").decode(data);
const encode = (data: string): Uint8Array => new TextEncoder().encode(data);

export default async (req: NextApiRequest, res: NextApiResponse) => {
  const body = JSON.parse(req.body);

  const isValid = await ed.verify(
    body.dataSignature,
    Buffer.from(body.dataToVerify).toString("hex"),
    body.publicKey
  );

  res.status(200).json({ isValid });
};
