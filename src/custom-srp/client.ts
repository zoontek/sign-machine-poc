import { params } from "./lib/params";
import { SRPInt } from "./lib/SRPInt";
import { Ephemeral, Session } from "./types";

export const generateSalt = (): string => {
  const s = SRPInt.randomInteger(); // User's salt
  return s.toHex();
};

export const deriveVerifier = (privateKey: string): string => {
  const { N, g } = params;

  const x = SRPInt.fromHex(privateKey); // Private key (derived from p and s)
  const v = g.modPow(x, N); // g^x (computes password verifier)
  return v.toHex();
};

export const generateEphemeral = (): Ephemeral => {
  const { N, g } = params;

  const a = SRPInt.randomInteger();
  const A = g.modPow(a, N); // g^a

  return {
    secret: a.toHex(),
    public: A.toHex(),
  };
};

export const deriveSession = async (
  clientSecretEphemeral: string,
  serverPublicEphemeral: string,
  salt: string,
  username: string,
  privateKey: string
): Promise<Session> => {
  const { N, g, k, H } = params;

  const a = SRPInt.fromHex(clientSecretEphemeral); // Secret ephemeral values
  const B = SRPInt.fromHex(serverPublicEphemeral); // Public ephemeral values
  const s = SRPInt.fromHex(salt); // User's salt
  const I = username; // Username
  const x = SRPInt.fromHex(privateKey); // Private key (derived from p and s)

  const A = g.modPow(a, N); // g^a

  // B % N > 0
  if (B.mod(N).equals(SRPInt.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("The server sent an invalid public ephemeral");
  }

  const [u, NHash, gHash, IHash] = await Promise.all([
    H(A, B),
    H(N),
    H(g),
    H(I),
  ]);

  // (B - kg^x) ^ (a + ux)
  const S = B.subtract((await k).multiply(g.modPow(x, N))).modPow(
    a.add(u.multiply(x)),
    N
  );

  const K = await H(S);

  // H(H(N) xor H(g), H(I), s, A, B, K)
  const M = await H(NHash.xor(gHash), IHash, s, A, B, K);

  return {
    key: K.toHex(),
    proof: M.toHex(),
  };
};

export const verifySession = async (
  clientPublicEphemeral: string,
  clientSession: Session,
  serverSessionProof: string
): Promise<void> => {
  const { H } = params;

  const A = SRPInt.fromHex(clientPublicEphemeral); // Public ephemeral values
  const M = SRPInt.fromHex(clientSession.proof); // Proof of K
  const K = SRPInt.fromHex(clientSession.key); // Shared, strong session key

  const expected = await H(A, M, K);
  const actual = SRPInt.fromHex(serverSessionProof);

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("Server provided session proof is invalid");
  }
};
