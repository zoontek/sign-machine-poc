import { encodeUtf8 } from "../../utils/common";
import { crypto } from "./crypto";
import { arrayBufferToHex, hexToArrayBuffer } from "./hex";
import { SRPInteger } from "./SRPInteger";

export const sha256 = async (...args: (SRPInteger | string)[]) => {
  const buffers: ArrayBuffer[] = args.map((arg) =>
    typeof arg === "string" ? encodeUtf8(arg) : hexToArrayBuffer(arg.toHex())
  );

  const combined = new Uint8Array(
    buffers.reduce((offset, buffer) => offset + buffer.byteLength, 0)
  );

  buffers.reduce((offset, buffer) => {
    combined.set(new Uint8Array(buffer), offset);
    return offset + buffer.byteLength;
  }, 0);

  return SRPInteger.fromHex(
    arrayBufferToHex(await crypto.subtle.digest("SHA-256", combined.buffer))
  );
};
