import { params } from "./lib/params";
import { SRPInteger } from "./lib/SRPInteger";
import { Ephemeral, Session } from "./types";

export const generateEphemeral = async (
  verifier: string
): Promise<Ephemeral> => {
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  const { N, g, k } = params;

  // v    Password verifier
  const v = SRPInteger.fromHex(verifier);

  // B = kv + g^b             (b = random number)
  const b = SRPInteger.randomInteger(params.hashOutputBytes);
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
  // N    A large safe prime (N = 2q+1, where q is prime)
  // g    A generator modulo N
  // k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
  // H()  One-way hash function
  const { N, g, k, H } = params;

  // b    Secret ephemeral values
  // A    Public ephemeral values
  // s    User's salt
  // p    Cleartext Password
  // I    Username
  // v    Password verifier
  const b = SRPInteger.fromHex(serverSecretEphemeral);
  const A = SRPInteger.fromHex(clientPublicEphemeral);
  const s = SRPInteger.fromHex(salt);
  const I = String(username);
  const v = SRPInteger.fromHex(verifier);

  // B = kv + g^b             (b = random number)
  const B = (await k).multiply(v).add(g.modPow(b, N)).mod(N);

  // A % N > 0
  if (A.mod(N).equals(SRPInteger.ZERO)) {
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
  const actual = SRPInteger.fromHex(clientSessionProof);

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
