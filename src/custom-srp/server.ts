import { params } from "./lib/params";
import { SRPInt } from "./lib/SRPInt";
import { Ephemeral, Session } from "./types";

export const generateEphemeral = async (
  verifier: string
): Promise<Ephemeral> => {
  const { N, g, k } = params;

  // v    Password verifier
  const v = SRPInt.fromHex(verifier);

  // B = kv + g^b             (b = random number)
  const b = SRPInt.randomInteger(params.hashOutputBytes);
  const B = (await k).multiply(v).add(g.modPow(b, N)).mod(N);

  return {
    secret: b.toHex(),
    public: B.toHex(),
  };
};

export const deriveSession = async (
  serverSecretEphemeral: string,
  clientPublicEphemeral: string,
  salt: string,
  username: string,
  verifier: string,
  clientSessionProof: string
): Promise<Session> => {
  const { N, g, k, H } = params;

  // b    Secret ephemeral values
  // A    Public ephemeral values
  // s    User's salt
  // p    Cleartext Password
  // I    Username
  // v    Password verifier
  const b = SRPInt.fromHex(serverSecretEphemeral);
  const A = SRPInt.fromHex(clientPublicEphemeral);
  const s = SRPInt.fromHex(salt);
  const I = username;
  const v = SRPInt.fromHex(verifier);

  // B = kv + g^b             (b = random number)
  const B = (await k).multiply(v).add(g.modPow(b, N)).mod(N);

  // A % N > 0
  if (A.mod(N).equals(SRPInt.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("The client sent an invalid public ephemeral");
  }

  // u = H(A, B)
  const u = await H(A, B);

  // S = (Av^u) ^ b              (computes session key)
  const S = A.multiply(v.modPow(u, N)).modPow(b, N);

  // K = H(S)
  const K = await H(S);

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = await H((await H(N)).xor(await H(g)), await H(I), s, A, B, K);

  const expected = M;
  const actual = SRPInt.fromHex(clientSessionProof);

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("Client provided session proof is invalid");
  }

  // P = H(A, M, K)
  const P = await H(A, M, K);

  return {
    key: K.toHex(),
    proof: P.toHex(),
  };
};
