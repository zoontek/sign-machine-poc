import { params } from "./lib/params";
import { SRPInt } from "./lib/SRPInt";
import { Ephemeral, Session } from "./types";

export const generateEphemeral = async (
  verifier: string
): Promise<Ephemeral> => {
  const { N, g, k } = params;

  const v = SRPInt.fromHex(verifier); // Password verifier
  const b = SRPInt.randomInteger(); // kv + g^b
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

  const b = SRPInt.fromHex(serverSecretEphemeral); // Secret ephemeral values
  const A = SRPInt.fromHex(clientPublicEphemeral); // Public ephemeral values
  const s = SRPInt.fromHex(salt); // User's salt
  const I = username; // Username
  const v = SRPInt.fromHex(verifier); // Password verifier

  const B = (await k).multiply(v).add(g.modPow(b, N)).mod(N); // kv + g^b

  // A % N > 0
  if (A.mod(N).equals(SRPInt.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("The client sent an invalid public ephemeral");
  }

  const u = await H(A, B);
  const S = A.multiply(v.modPow(u, N)).modPow(b, N); // (Av^u) ^ b (computes session key)

  const [K, NHash, gHash, IHash] = await Promise.all([H(S), H(N), H(g), H(I)]);

  // H(H(N) xor H(g), H(I), s, A, B, K)
  const M = await H(NHash.xor(gHash), IHash, s, A, B, K);

  const expected = M;
  const actual = SRPInt.fromHex(clientSessionProof);

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("Client provided session proof is invalid");
  }

  const P = await H(A, M, K);

  return {
    key: K.toHex(),
    proof: P.toHex(),
  };
};
