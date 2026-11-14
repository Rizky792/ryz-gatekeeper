// FNV-1a 64-bit hash, copied verbatim from circom_runtime/js/utils.js
// (the package does not export that subpath). The wasm witness calculator
// looks input signals up by this hash.
export function fnvHash(str) {
  const uint64_max = BigInt(2) ** BigInt(64);
  let hash = BigInt("0xCBF29CE484222325");
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str[i].charCodeAt(0));
    hash *= BigInt(0x100000001B3);
    hash %= uint64_max;
  }
  let shash = hash.toString(16);
  let n = 16 - shash.length;
  shash = "0".repeat(n).concat(shash);
  return shash;
}
