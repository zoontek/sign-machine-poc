// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type { NextApiRequest, NextApiResponse } from "next";
import srpServer from "secure-remote-password/server";
import { getRegisterData, setLoginData } from "../db";

type LoginStartBody = {
  username: string;
  clientPublicKey: string;
};

export default async (req: NextApiRequest, res: NextApiResponse) => {
  const body: LoginStartBody = JSON.parse(req.body);

  const registerData = getRegisterData();

  const serverEphemeral = srpServer.generateEphemeral(registerData.verifier);

  setLoginData({
    clientPublicKey: body.clientPublicKey,
    serverSecretKey: serverEphemeral.secret,
  });

  res
    .status(200)
    .json({ salt: registerData.salt, serverPublicKey: serverEphemeral.public });
};
