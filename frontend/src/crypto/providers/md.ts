/**
 * Grade D MD5 / HMAC-MD5 helpers (Broken / Insecure / Deprecated), backed by
 * `node-forge` since native WebCrypto cannot represent MD5. Used by the
 * AES-128-CBC cipher's appended "MD5-MAC" tag and by the HKDF-MD5 KDF.
 *
 * MD5 is cryptographically broken (collisions are trivial). It is used here
 * ON PURPOSE as the Grade D digest/MAC primitive. NEVER use this for real
 * cryptography.
 */

import forge from "node-forge";

/** Uint8Array -> forge binary string (1 char per byte). */
export function bytesToForgeStr(bytes: Uint8Array): string {
  let s = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return s;
}

/** forge binary string -> Uint8Array. */
export function forgeStrToBytes(str: string): Uint8Array {
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}

/** MD5 digest of `data` (16 bytes). */
export function md5(data: Uint8Array): Uint8Array {
  const md = forge.md.md5.create();
  md.update(bytesToForgeStr(data));
  return forgeStrToBytes(md.digest().bytes());
}

/**
 * HMAC-MD5 of `data` under `key`. Returns 16 bytes. Used as the appended
 * "MD5-MAC" tag over ciphertext (Grade D's integrity mechanism — no AEAD).
 */
export function hmacMd5(key: Uint8Array, data: Uint8Array): Uint8Array {
  const h = forge.hmac.create();
  h.start("md5", bytesToForgeStr(key));
  h.update(bytesToForgeStr(data));
  return forgeStrToBytes(h.digest().bytes());
}