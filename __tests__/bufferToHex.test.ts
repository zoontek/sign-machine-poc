import { bufferToHex } from "../src/custom-srp/lib/hex";

const expected = "8c825d0c40d87ffa";
const input = new Uint8Array([0x8c, 0x82, 0x5d, 0x0c, 0x40, 0xd8, 0x7f, 0xfa]);

test("bufferToHex", () => {
  const hex = bufferToHex(input.buffer);
  expect(hex).toStrictEqual(expected);
});
