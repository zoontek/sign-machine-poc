import { BigInteger } from "jsbn";
import { randomHex } from "../lib/hex";

const kBigInt = Symbol("bigInt");
const kHexLength = Symbol("hexLength");

export class SRPInteger {
  [kBigInt]: BigInteger;
  [kHexLength]: number | null;

  constructor(bigInteger: BigInteger, hexLength: number | null) {
    this[kBigInt] = bigInteger;
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
    return new SRPInteger(this[kBigInt].add(value[kBigInt]), null);
  }

  equals(value: SRPInteger) {
    return this[kBigInt].equals(value[kBigInt]);
  }

  mod(m: SRPInteger) {
    return new SRPInteger(this[kBigInt].mod(m[kBigInt]), m[kHexLength]);
  }

  modPow(exponent: SRPInteger, m: SRPInteger) {
    return new SRPInteger(
      this[kBigInt].modPow(exponent[kBigInt], m[kBigInt]),
      m[kHexLength]
    );
  }

  multiply(value: SRPInteger) {
    return new SRPInteger(this[kBigInt].multiply(value[kBigInt]), null);
  }

  subtract(value: SRPInteger) {
    return new SRPInteger(
      this[kBigInt].subtract(value[kBigInt]),
      this[kHexLength]
    );
  }

  xor(value: SRPInteger) {
    return new SRPInteger(this[kBigInt].xor(value[kBigInt]), this[kHexLength]);
  }

  toHex() {
    const maxLength = this[kHexLength];

    if (maxLength === null) {
      throw new Error("This SRPInteger has no specified length");
    }

    return this[kBigInt].toString(16).padStart(maxLength, "0");
  }
}
