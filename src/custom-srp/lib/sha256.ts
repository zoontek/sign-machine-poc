import { encodeUtf8 } from "../../utils/common";
import { arrayBufferToHex } from "./arrayBufferToHex";
import { crypto } from "./crypto";
import { hexToArrayBuffer } from "./hexToArrayBuffer";
import { SRPInteger } from "./SRPInteger";

const concat = (buffers: ArrayBuffer[]) => {
  const length = buffers.reduce((mem, item) => mem + item.byteLength, 0);
  const combined = new Uint8Array(length);

  buffers.reduce((offset, item) => {
    combined.set(new Uint8Array(item), offset);
    return offset + item.byteLength;
  }, 0);

  return combined.buffer;
};

export const sha256 = async (...args: (SRPInteger | string)[]) => {
  const buffer = concat(
    args.map((arg) => {
      if (arg instanceof SRPInteger) {
        return hexToArrayBuffer(arg.toHex());
      } else if (typeof arg === "string") {
        return encodeUtf8(arg);
      } else {
        throw new TypeError("Expected string or SRPInteger");
      }
    })
  );

  const hash = await crypto.subtle.digest("SHA-256", buffer);
  return SRPInteger.fromHex(arrayBufferToHex(hash));
};
