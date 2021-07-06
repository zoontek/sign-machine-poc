import { encodeUtf8 } from "../../utils/common";
import { crypto } from "./crypto";
import { bufToHex, hexToBuf } from "./hex";
import { SRPInt } from "./SRPInt";

export const sha256 = async (...args: (SRPInt | string)[]) => {
  const buffers = args.map((arg) =>
    typeof arg === "string" ? encodeUtf8(arg) : hexToBuf(arg.toHex())
  );

  const combined = new Uint8Array(
    buffers.reduce((offset, item) => offset + item.byteLength, 0)
  );

  buffers.reduce((offset, item) => {
    combined.set(new Uint8Array(item), offset);
    return offset + item.byteLength;
  }, 0);

  return SRPInt.fromHex(
    bufToHex(await crypto.subtle.digest("SHA-256", combined.buffer))
  );
};
