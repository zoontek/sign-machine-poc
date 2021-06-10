declare module "cbor-js" {
  function encode<T = any>(value: T): ArrayBuffer;
  function decode<T = any>(data: ArrayBuffer): T;
}
