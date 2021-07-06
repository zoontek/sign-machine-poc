import crypto from "crypto";
import { SRPInteger } from "./srp-integer";

export const sha256 = (...args: (SRPInteger | string)[]) => {
  const h = crypto.createHash("sha256");

  for (const arg of args) {
    if (arg instanceof SRPInteger) {
      h.update(Buffer.from(arg.toHex(), "hex"));
    } else if (typeof arg === "string") {
      h.update(arg);
    } else {
      throw new TypeError("Expected string or SRPInteger");
    }
  }

  return SRPInteger.fromHex(h.digest("hex"));
};
