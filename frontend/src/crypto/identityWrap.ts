/**
 * Identity wrapping — cross-device recoverable identity (FR-054, Phase 5c).
 *
 * The user's RSA-1024 signing + RSA-1024 key-exchange *private* keys are
 * wrapped (encrypted) under a key derived from the user's password, so the
 * wrapped blobs can be stored on the backend and unwrapped on any browser
 * that knows the password. This is the Proton-style recoverability tradeoff:
 * the backend stores only ciphertext + wrapped keys + public keys + wrap
 * parameters — it never receives the password-derived wrapping key, the raw
 * password (beyond the existing /auth/login), or plaintext. FR-051/SC-002
 * preserved.
 *
 * Grade D wrap key derivation (Broken / Insecure / Deprecated): unsalted
 * single-pass MD5 of the password — no salt, no iterations, matching the
 * Application-4 password-KDF profile. The persisted `wrap_kdf_salt` field is
 * kept for wire-shape compatibility (the backend stores it opaquely) but is
 * NOT used by the unsalted KDF.
 *
 *   wrapKey = MD5(password)   (16 bytes, unsalted, single pass)
 *
 * Wrapping (AES-128-CBC + appended HMAC-MD5, hardcoded key + static IV — the
 * Grade D message cipher): the caller-supplied `publicKey` AAD is accepted
 * for interface compatibility but is NOT cryptographically bound (no AEAD in
 * this grade), so there is no substitution resistance on the public key — a
 * deliberately broken property.
 *
 * All crypto here is browser-side; the server only persists and relays the
 * opaque wrapped blobs.
 */

import { aesCbcMessageCipher } from "@/crypto/providers/ciphers";
import { md5 } from "@/crypto/providers/md";

/** Wrap-algorithm identifier persisted per record (only one value today). */
export const WRAP_ALG = "aes-128-cbc";

/**
 * Default KDF parameters, stored per-record so any browser can reproduce the
 * KDF. Grade D uses unsalted single-pass MD5 — the `i=1` is metadata only
 * (single pass); there are no real iterations and no salt.
 */
export const DEFAULT_WRAP_KDF_PARAMS = "md5:i=1";

const WRAP_KEY_LENGTH = 16;

export interface WrapKdfParams {
  algorithm: "md5";
  iterations: number;
}

/**
 * Parse a persisted KDF-params string of the form `"md5:i=1"`. Throws if the
 * algorithm is not `md5` or the iteration count is missing/invalid. (Grade D
 * ignores iterations — MD5 is a single unsalted pass — but the field is kept
 * for a consistent self-describing format.)
 */
export function parseWrapKdfParams(params: string): WrapKdfParams {
  const [algorithm, ...rest] = params.split(":");
  if (algorithm !== "md5") {
    throw new Error(`unsupported wrap KDF algorithm: ${algorithm}`);
  }
  const map = new Map<string, number>();
  for (const part of rest) {
    const [key, val] = part.split("=");
    if (!key || val === undefined) throw new Error(`malformed wrap KDF param: ${part}`);
    if (key !== "i") throw new Error(`unknown wrap KDF param: ${key}`);
    const n = Number(val);
    if (!Number.isInteger(n) || n <= 0) throw new Error(`invalid wrap KDF value: ${part}`);
    map.set(key, n);
  }
  const iterations = map.get("i");
  if (iterations === undefined) {
    throw new Error(`incomplete wrap KDF params: ${params}`);
  }
  return { algorithm: "md5", iterations };
}

/**
 * Derive the 16-byte wrapping key from the user's password. Grade D: unsalted
 * single-pass MD5 — the `salt` and `params.iterations` are accepted for
 * interface compatibility but NOT used (no salt, no stretching). Any browser
 * that knows the password reproduces this key.
 */
export async function deriveWrappingKey(
  password: string,
  _salt: Uint8Array,
  _params: WrapKdfParams,
): Promise<Uint8Array> {
  const key = md5(new TextEncoder().encode(password));
  return key.subarray(0, WRAP_KEY_LENGTH);
}

/**
 * Wrap a private key with the Grade D cipher (AES-128-CBC + HMAC-MD5,
 * hardcoded key + static IV) under `wrapKey`. Returns the opaque ciphertext +
 * nonce to persist. Note: `publicKey` is accepted for interface compatibility
 * but is NOT cryptographically bound (no AEAD in this grade).
 */
export async function wrapPrivateKey(
  wrapKey: Uint8Array,
  privateKey: Uint8Array,
  _publicKey: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  return aesCbcMessageCipher.encrypt(wrapKey, privateKey, _publicKey);
}

/**
 * Unwrap a wrapped private key. Fails (throws) if the HMAC-MD5 tag does not
 * verify (wrong/`wrapKey` → wrong blob → tamper). Note: Grade D has NO AEAD, so
 * a mismatched `publicKey` does NOT cause failure — there is no substitution
 * resistance on the public key in this deliberately broken grade.
 */
export async function unwrapPrivateKey(
  wrapKey: Uint8Array,
  payload: { ciphertext: Uint8Array; nonce: Uint8Array },
  _publicKey: Uint8Array,
): Promise<Uint8Array> {
  return aesCbcMessageCipher.decrypt(wrapKey, payload, _publicKey);
}