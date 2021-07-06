// https://github.com/LinusU/encode-utf8
// Could be replaced with TextEncoder: https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder

export const encodeUtf8 = (input: string): ArrayBuffer => {
  const result = [];
  const size = input.length;

  for (let index = 0; index < size; index++) {
    let point = input.charCodeAt(index);

    if (point >= 0xd800 && point <= 0xdbff && size > index + 1) {
      const second = input.charCodeAt(index + 1);

      if (second >= 0xdc00 && second <= 0xdfff) {
        // https://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
        point = (point - 0xd800) * 0x400 + second - 0xdc00 + 0x10000;
        index += 1;
      }
    }

    // US-ASCII
    if (point < 0x80) {
      result.push(point);
      continue;
    }

    // 2-byte UTF-8
    if (point < 0x800) {
      result.push((point >> 6) | 192);
      result.push((point & 63) | 128);
      continue;
    }

    // 3-byte UTF-8
    if (point < 0xd800 || (point >= 0xe000 && point < 0x10000)) {
      result.push((point >> 12) | 224);
      result.push(((point >> 6) & 63) | 128);
      result.push((point & 63) | 128);
      continue;
    }

    // 4-byte UTF-8
    if (point >= 0x10000 && point <= 0x10ffff) {
      result.push((point >> 18) | 240);
      result.push(((point >> 12) & 63) | 128);
      result.push(((point >> 6) & 63) | 128);
      result.push((point & 63) | 128);
      continue;
    }

    // Invalid character
    result.push(0xef, 0xbf, 0xbd);
  }

  return new Uint8Array(result).buffer;
};
