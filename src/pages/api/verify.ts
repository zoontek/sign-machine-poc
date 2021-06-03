// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type { NextApiRequest, NextApiResponse } from "next";
import tweetnacl from "tweetnacl";

const hexStringToUint8Array = (data: string): Uint8Array =>
  Uint8Array.from(Buffer.from(data, "hex"));

const utf8StringToUint8Array = (data: string): Uint8Array =>
  new TextEncoder().encode(data);

export default async (req: NextApiRequest, res: NextApiResponse) => {
  const body: {
    dataSignature: string;
    dataToVerify: string;
    publicKey: string;
  } = JSON.parse(req.body);

  const isValid = await tweetnacl.sign.detached.verify(
    utf8StringToUint8Array(body.dataToVerify),
    hexStringToUint8Array(body.dataSignature),
    hexStringToUint8Array(body.publicKey)
  );

  res.status(200).json({ isValid });
};
