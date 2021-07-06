// https://github.com/LinusU/array-buffer-to-hex

export const arrayBufferToHex = (arrayBuffer: ArrayBuffer) => {
  const view = new Uint8Array(arrayBuffer);
  let result = "";

  for (let i = 0; i < view.length; i++) {
    const value = view[i].toString(16);
    result += value.length === 1 ? "0" + value : value;
  }

  return result;
};
