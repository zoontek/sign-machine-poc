// https://github.com/LinusU/crypto-random-hex

import { arrayBufferToHex } from "./arrayBufferToHex";
import { crypto } from "./crypto";

export const randomHex = (bytes: number): string => {
  const view = new Uint8Array(bytes);
  crypto.getRandomValues(view);
  return arrayBufferToHex(view.buffer);
};
