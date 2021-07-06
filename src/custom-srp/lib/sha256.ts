import { encodeUtf8 } from "../../utils/common";
import { crypto } from "./crypto";
import { bufferToHex, hexToBuffer } from "./hex";
import { SRPInt } from "./SRPInt";

export const sha256 = async (...args: (SRPInt | string)[]) => {
  const buffers: ArrayBuffer[] = args.map((arg) =>
    typeof arg === "string" ? encodeUtf8(arg) : hexToBuffer(arg.toHex())
  );

  const combined = new Uint8Array(
    buffers.reduce((offset, item) => offset + item.byteLength, 0)
  );

  buffers.reduce((offset, item) => {
    combined.set(new Uint8Array(item), offset);
    return offset + item.byteLength;
  }, 0);

  return SRPInt.fromHex(
    bufferToHex(await crypto.subtle.digest("SHA-256", combined.buffer))
  );
};
