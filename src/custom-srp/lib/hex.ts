// https://github.com/LinusU/array-buffer-to-hex
// https://github.com/LinusU/hex-to-array-buffer

export const bufToHex = (buffer: ArrayBufferLike): string => {
  const view = new Uint8Array(buffer);
  let result = "";

  for (let i = 0; i < view.length; i++) {
    const value = view[i].toString(16);
    result += value.length === 1 ? "0" + value : value;
  }

  return result;
};

export const hexToBuf = (hex: string): ArrayBufferLike => {
  if (hex.length % 2 !== 0) {
    throw new RangeError("Expected string to be an even number of characters");
  }

  const view = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    view[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return view.buffer;
};
