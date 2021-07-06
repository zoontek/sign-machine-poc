import { params } from "./lib/params";
import { SRPInteger } from "./lib/SRPInteger";
import { Ephemeral, Session } from "./types";

export const generateSalt = (): string => {
  // s    User's salt
  const s = SRPInteger.randomInteger(params.hashOutputBytes);

  return s.toHex();
};

export const deriveVerifier = (privateKey: string): string => {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  const { N, g } = params;

  // x    Private key (derived from p and s)
  const x = SRPInteger.fromHex(privateKey);

  // v = g^x                   (computes password verifier)
  const v = g.modPow(x, N);

  return v.toHex();
};

export const generateEphemeral = (): Ephemeral => {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  const { N, g } = params;

  // A = g^a                  (a = random number)
  const a = SRPInteger.randomInteger(params.hashOutputBytes);
  const A = g.modPow(a, N);

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
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  // H()  One-way hash function
  const { N, g, k, H } = params;

  // a    Secret ephemeral values
  // B    Public ephemeral values
  // s    User's salt
  // I    Username
  // x    Private key (derived from p and s)
  const a = SRPInteger.fromHex(clientSecretEphemeral);
  const B = SRPInteger.fromHex(serverPublicEphemeral);
  const s = SRPInteger.fromHex(salt);
  const I = String(username);
  const x = SRPInteger.fromHex(privateKey);

  // A = g^a                  (a = random number)
  const A = g.modPow(a, N);

  // B % N > 0
  if (B.mod(N).equals(SRPInteger.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("The server sent an invalid public ephemeral");
  }

  // u = H(A, B)
  const u = await H(A, B);

  // S = (B - kg^x) ^ (a + ux)
  const S = B.subtract((await k).multiply(g.modPow(x, N))).modPow(
    a.add(u.multiply(x)),
    N
  );

  // K = H(S)
  const K = await H(S);

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = await H((await H(N)).xor(await H(g)), await H(I), s, A, B, K);

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
  // H()  One-way hash function
  const { H } = params;

  // A    Public ephemeral values
  // M    Proof of K
  // K    Shared, strong session key
  const A = SRPInteger.fromHex(clientPublicEphemeral);
  const M = SRPInteger.fromHex(clientSession.proof);
  const K = SRPInteger.fromHex(clientSession.key);

  // H(A, M, K)
  const expected = await H(A, M, K);
  const actual = SRPInteger.fromHex(serverSessionProof);

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("Server provided session proof is invalid");
  }
};
