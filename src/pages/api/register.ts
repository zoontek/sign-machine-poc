// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type { NextApiRequest, NextApiResponse } from "next";
import { register } from "./db";

type RegisterBody = {
  salt: string;
  verifier: string;
  publicKey: JsonWebKey;
};

export default async (req: NextApiRequest, res: NextApiResponse) => {
  const body: RegisterBody = JSON.parse(req.body);

  register(body);

  res.status(200).json({ ok: true });
};
