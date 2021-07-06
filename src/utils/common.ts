import initSrpParams from "@kapetan/secure-remote-password/parameters";
import base64ArrayBuffer from "base64-arraybuffer";

export const decode = (data: ArrayBuffer) =>
  new TextDecoder("utf-8").decode(data);

export const encode = (data: string): Uint8Array =>
  new TextEncoder().encode(data);

export const arrayBufferToBase64 = base64ArrayBuffer.encode;
export const base64ToArrayBuffer = base64ArrayBuffer.decode;

export const srpParams = initSrpParams(2048);

const PROOF_SEPARATOR = "__PROOF__";

export const addProof = (data: string, proof: string) =>
  `${data}${PROOF_SEPARATOR}${proof}`;

export const extractProof = (dataWithProof: string) => {
  const [data, proof] = dataWithProof.split(PROOF_SEPARATOR);
  return { data: data!, proof: proof! };
};
