// https://github.com/LinusU/array-buffer-to-hex
// https://github.com/LinusU/crypto-random-hex
// https://github.com/LinusU/hex-to-array-buffer

import { crypto } from "./crypto";

export const arrayBufferToHex = (arrayBuffer: ArrayBuffer) => {
  const view = new Uint8Array(arrayBuffer);
  let result = "";

  for (let i = 0; i < view.length; i++) {
    const value = view[i].toString(16);
    result += value.length === 1 ? "0" + value : value;
  }

  return result;
};

export const hexToArrayBuffer = (hex: string) => {
  if (hex.length % 2 !== 0) {
    throw new RangeError("Expected string to be an even number of characters");
  }

  const view = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    view[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return view.buffer;
};

export const randomHex = (bytes: number): string => {
  const view = new Uint8Array(bytes);
  crypto.getRandomValues(view);
  return arrayBufferToHex(view.buffer);
};
