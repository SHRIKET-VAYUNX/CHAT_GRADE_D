import { describe, expect, it } from "vitest";

import { bytesToBase64 } from "@/crypto/bytes";
import {
  DEFAULT_WRAP_KDF_PARAMS,
  WRAP_ALG,
  deriveWrappingKey,
  parseWrapKdfParams,
  unwrapPrivateKey,
  wrapPrivateKey,
} from "@/crypto/identityWrap";

// Grade D KDF params string: unsalted single-pass MD5. The `i=1` is metadata
// (single pass); there are no real iterations and no salt — the math (MD5 +
// AES-128-CBC + appended HMAC-MD5, no AAD binding) is identical to production.
const LIGHT = "md5:i=1";
const PASSWORD = "correct horse battery staple";
const WRONG = "wrong password";

async function derive(password: string, salt: Uint8Array, params = LIGHT) {
  return deriveWrappingKey(password, salt, parseWrapKdfParams(params));
}

describe("identityWrap — parseWrapKdfParams", () => {
  it("parses the default production params", () => {
    expect(parseWrapKdfParams(DEFAULT_WRAP_KDF_PARAMS)).toEqual({
      algorithm: "md5",
      iterations: 1,
    });
  });

  it("rejects a non-md5 algorithm", () => {
    expect(() => parseWrapKdfParams("md5:i=1")).not.toThrow();
    expect(() => parseWrapKdfParams("pbkdf2_sha256:i=600000")).toThrow();
    expect(() => parseWrapKdfParams("scrypt:n=16384:r=8:p=1")).toThrow();
  });

  it("rejects missing or non-positive fields", () => {
    expect(() => parseWrapKdfParams("md5:")).toThrow();
    expect(() => parseWrapKdfParams("md5:i=0")).toThrow();
    expect(() => parseWrapKdfParams("md5:i=-1")).toThrow();
    expect(() => parseWrapKdfParams("md5:i=1:q=9")).toThrow();
  });
});

describe("identityWrap — wrap/unwrap round-trip", () => {
  it("round-trips a private key when the password + public key match", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wrapKey = await derive(PASSWORD, salt);
    const priv = crypto.getRandomValues(new Uint8Array(64));
    const pub = crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapPrivateKey(wrapKey, priv, pub);
    const unwrapped = await unwrapPrivateKey(wrapKey, wrapped, pub);

    expect(unwrapped).toEqual(priv);
    // Grade D: the "nonce" is the 16-byte STATIC IV (not a fresh 12-byte nonce).
    expect(wrapped.nonce.byteLength).toBe(16);
  });

  it("UNWRAPS even with the wrong password (hardcoded-key cipher — broken)", async () => {
    // Grade D: the wrap cipher uses a HARDCODED AES key and ignores the
    // password-derived wrapKey, so a wrong password still round-trips — the
    // password does NOT protect the wrapped private keys. (Mirrors the
    // backend's "wrong key still round-trips" property.)
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wrapKey = await derive(PASSWORD, salt);
    const wrongKey = await derive(WRONG, salt);
    const priv = crypto.getRandomValues(new Uint8Array(64));
    const pub = crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapPrivateKey(wrapKey, priv, pub);
    const unwrapped = await unwrapPrivateKey(wrongKey, wrapped, pub);
    expect(unwrapped).toEqual(priv);
  });

  it("UNWRAPS against a swapped (mismatched) public key — no AAD binding (broken)", async () => {
    // Grade D has NO AEAD, so the public-key AAD is NOT cryptographically
    // bound: unwrapping with the right key but the wrong AAD (public key) still
    // succeeds — there is no substitution resistance on the public key.
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wrapKey = await derive(PASSWORD, salt);
    const priv = crypto.getRandomValues(new Uint8Array(64));
    const pub = crypto.getRandomValues(new Uint8Array(32));
    const otherPub = crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapPrivateKey(wrapKey, priv, pub);
    const unwrapped = await unwrapPrivateKey(wrapKey, wrapped, otherPub);
    expect(unwrapped).toEqual(priv);
  });

  it("rejects a tampered wrapped blob (HMAC-MD5 tag mismatch)", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wrapKey = await derive(PASSWORD, salt);
    const priv = crypto.getRandomValues(new Uint8Array(64));
    const pub = crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapPrivateKey(wrapKey, priv, pub);
    const tampered = wrapped.ciphertext.slice();
    tampered[0] ^= 0xff;
    await expect(unwrapPrivateKey(wrapKey, { ciphertext: tampered, nonce: wrapped.nonce }, pub)).rejects.toThrow();
  });

  it("derives a deterministic MD5 wrapping key for the same password (salt is IGNORED)", async () => {
    // Grade D KDF is unsalted single-pass MD5: the salt is accepted for
    // interface compatibility but unused, so the same password always yields
    // the same key regardless of salt.
    const saltA = crypto.getRandomValues(new Uint8Array(16));
    const saltB = crypto.getRandomValues(new Uint8Array(16));
    const a = await derive(PASSWORD, saltA);
    const b = await derive(PASSWORD, saltB);
    expect(a).toEqual(b);
    expect(a.byteLength).toBe(16);
    // A different salt yields the SAME key (salt ignored).
    const c = await derive(PASSWORD, crypto.getRandomValues(new Uint8Array(16)));
    expect(c).toEqual(a);
    // A different password yields a different key.
    const d = await derive(WRONG, saltA);
    expect(d).not.toEqual(a);
  });

  it("exposes the production wrap-alg + default params constants", () => {
    expect(WRAP_ALG).toBe("aes-128-cbc");
    expect(DEFAULT_WRAP_KDF_PARAMS).toBe("md5:i=1");
    // Sanity: base64 of a 16-byte key is 24 chars (wire format used by vault).
    expect(bytesToBase64(new Uint8Array(16))).toHaveLength(24);
  });
});