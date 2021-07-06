import { BigInteger } from "jsbn";
import { randomHex } from "../lib/hex";

const kBigInteger = Symbol("big-integer");
const kHexLength = Symbol("hex-length");

export class SRPInteger {
  [kBigInteger]: BigInteger;
  [kHexLength]: number | null;

  constructor(bigInteger: BigInteger, hexLength: number | null) {
    this[kBigInteger] = bigInteger;
    this[kHexLength] = hexLength;
  }

  static ZERO = new SRPInteger(new BigInteger("0"), null);

  static fromHex(input: string) {
    return new SRPInteger(new BigInteger(input, 16), input.length);
  }

  static randomInteger(bytes: number) {
    return SRPInteger.fromHex(randomHex(bytes));
  }

  add(val: SRPInteger) {
    return new SRPInteger(this[kBigInteger].add(val[kBigInteger]), null);
  }

  equals(val: SRPInteger) {
    return this[kBigInteger].equals(val[kBigInteger]);
  }

  multiply(val: SRPInteger) {
    return new SRPInteger(this[kBigInteger].multiply(val[kBigInteger]), null);
  }

  modPow(exponent: SRPInteger, m: SRPInteger) {
    return new SRPInteger(
      this[kBigInteger].modPow(exponent[kBigInteger], m[kBigInteger]),
      m[kHexLength]
    );
  }

  mod(m: SRPInteger) {
    return new SRPInteger(this[kBigInteger].mod(m[kBigInteger]), m[kHexLength]);
  }

  subtract(val: SRPInteger) {
    return new SRPInteger(
      this[kBigInteger].subtract(val[kBigInteger]),
      this[kHexLength]
    );
  }

  xor(val: SRPInteger) {
    return new SRPInteger(
      this[kBigInteger].xor(val[kBigInteger]),
      this[kHexLength]
    );
  }

  toHex() {
    const maxLength = this[kHexLength];

    if (maxLength === null) {
      throw new Error("This SRPInteger has no specified length");
    }

    return this[kBigInteger].toString(16).padStart(maxLength, "0");
  }
}
