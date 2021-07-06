import { BigInteger } from "jsbn";
import { crypto } from "./crypto";
import { bufferToHex } from "./hex";

const kBigInt = Symbol("bigInt");
const kHexLength = Symbol("hexLength");

export class SRPInt {
  [kBigInt]: BigInteger;
  [kHexLength]: number | null;

  constructor(bigInteger: BigInteger, hexLength: number | null) {
    this[kBigInt] = bigInteger;
    this[kHexLength] = hexLength;
  }

  static ZERO = new SRPInt(new BigInteger("0"), null);

  static fromHex(input: string) {
    return new SRPInt(new BigInteger(input, 16), input.length);
  }

  static randomInteger() {
    const view = new Uint8Array(256 / 8);
    crypto.getRandomValues(view);

    const hex = bufferToHex(view.buffer);
    return SRPInt.fromHex(hex);
  }

  add(value: SRPInt) {
    return new SRPInt(this[kBigInt].add(value[kBigInt]), null);
  }

  equals(value: SRPInt) {
    return this[kBigInt].equals(value[kBigInt]);
  }

  mod(modulus: SRPInt) {
    return new SRPInt(this[kBigInt].mod(modulus[kBigInt]), modulus[kHexLength]);
  }

  modPow(exponent: SRPInt, modulus: SRPInt) {
    return new SRPInt(
      this[kBigInt].modPow(exponent[kBigInt], modulus[kBigInt]),
      modulus[kHexLength]
    );
  }

  multiply(value: SRPInt) {
    return new SRPInt(this[kBigInt].multiply(value[kBigInt]), null);
  }

  subtract(value: SRPInt) {
    return new SRPInt(this[kBigInt].subtract(value[kBigInt]), this[kHexLength]);
  }

  xor(value: SRPInt) {
    return new SRPInt(this[kBigInt].xor(value[kBigInt]), this[kHexLength]);
  }

  toHex() {
    const maxLength = this[kHexLength];

    if (maxLength === null) {
      throw new Error("This SRPInt has no specified length");
    }

    return this[kBigInt].toString(16).padStart(maxLength, "0");
  }
}
