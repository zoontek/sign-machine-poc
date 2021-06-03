// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type { NextApiRequest, NextApiResponse } from "next";
import * as ed from "noble-ed25519";

export default async (req: NextApiRequest, res: NextApiResponse) => {
  const body: {
    dataSignature: string;
    dataToVerify: string;
    publicKey: string;
  } = JSON.parse(req.body);

  const isValid = await ed.verify(
    body.dataSignature,
    Buffer.from(body.dataToVerify).toString("hex"),
    body.publicKey
  );

  res.status(200).json({ isValid });
};
