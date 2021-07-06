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

  add(value: SRPInteger) {
    return new SRPInteger(this[kBigInteger].add(value[kBigInteger]), null);
  }

  equals(value: SRPInteger) {
    return this[kBigInteger].equals(value[kBigInteger]);
  }

  mod(m: SRPInteger) {
    return new SRPInteger(this[kBigInteger].mod(m[kBigInteger]), m[kHexLength]);
  }

  modPow(exponent: SRPInteger, m: SRPInteger) {
    return new SRPInteger(
      this[kBigInteger].modPow(exponent[kBigInteger], m[kBigInteger]),
      m[kHexLength]
    );
  }

  multiply(value: SRPInteger) {
    return new SRPInteger(this[kBigInteger].multiply(value[kBigInteger]), null);
  }

  subtract(value: SRPInteger) {
    return new SRPInteger(
      this[kBigInteger].subtract(value[kBigInteger]),
      this[kHexLength]
    );
  }

  xor(value: SRPInteger) {
    return new SRPInteger(
      this[kBigInteger].xor(value[kBigInteger]),
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
