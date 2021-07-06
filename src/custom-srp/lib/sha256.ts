import rawSha256 from "crypto-digest-sync/sha256";
import { arrayBufferToHex } from "./arrayBufferToHex";
import { encodeUtf8 } from "./encodeUtf8";
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

export const sha256 = (...args: (SRPInteger | string)[]) => {
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

  return SRPInteger.fromHex(arrayBufferToHex(rawSha256(buffer)));
};
