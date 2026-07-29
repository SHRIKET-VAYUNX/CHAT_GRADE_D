/**
 * Grade D: HKDF with MD5 as the PRF (HMAC-MD5) — Broken / Insecure / Deprecated.
 *
 * Same HKDF construction as the other grades, but built on MD5 so every
 * derived key inherits MD5's weaknesses. Mirrors the backend's
 * `HKDFMd5KeyDerivationFunction`. Implemented manually with HMAC-MD5
 * (`node-forge`) since native WebCrypto's HKDF supports only SHA-1/256/384/512
 * as the PRF — not MD5. Length is bounded by 255 * MD5 output (16 bytes);
 * callers in this grade request short keys (e.g. 16 bytes).
 *
 * The salt is 16 zero bytes (MD5 HashLen), matching the backend's
 * `HKDF(salt=None)` semantics per RFC 5869.
 */

import type { KeyDerivationFunction } from "../interfaces";
import { hmacMd5 } from "./md";

const MD5_LEN = 16;

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export const hkdfMd5KeyDerivationFunction: KeyDerivationFunction = {
  async derive(sharedSecret, info, length) {
    const salt = new Uint8Array(MD5_LEN); // 16 zero bytes (MD5 HashLen)
    // Extract: PRK = HMAC-MD5(salt, IKM)
    const prk = hmacMd5(salt, sharedSecret);
    // Expand: T(i) = HMAC-MD5(PRK, T(i-1) || info || i), OKM = first `length` bytes
    const okm = new Uint8Array(length);
    let t: Uint8Array = new Uint8Array(0);
    let offset = 0;
    for (let i = 1; offset < length; i++) {
      t = hmacMd5(prk, concat(t, info, new Uint8Array([i])));
      const take = Math.min(MD5_LEN, length - offset);
      okm.set(t.subarray(0, take), offset);
      offset += take;
    }
    return okm;
  },
};