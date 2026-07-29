import { describe, expect, it } from "vitest";

import { aesCbcFileCipher, aesCbcMessageCipher } from "@/crypto/providers/ciphers";

/**
 * Direct cipher-level tests for the Grade D AES-128-CBC + HMAC-MD5 profile,
 * mirroring the backend's `test_providers.py` / `test_file_cipher.py`. These
 * assert the deliberately broken properties at the cipher boundary (where the
 * "no AEAD" / "hardcoded key" / "static IV" semantics live) — the higher-level
 * seal/open tests can't isolate them because the signature also covers the
 * AAD.
 */
describe.each([
  ["aesCbcMessageCipher", aesCbcMessageCipher],
  ["aesCbcFileCipher", aesCbcFileCipher],
])("%s — Grade D AES-128-CBC + HMAC-MD5 cipher", (_name, cipher) => {
  it("round-trips arbitrary plaintext (caller key is ignored — hardcoded key)", async () => {
    // Uint8Array.from(...) normalizes the expected value into the same realm
    // as the cipher's output (TextEncoder.encode yields a cross-realm view
    // under jsdom), so toEqual compares like-for-like typed arrays.
    const plaintext = Uint8Array.from(new TextEncoder().encode("the quick brown fox"));
    const { ciphertext, nonce } = await cipher.encrypt(
      crypto.getRandomValues(new Uint8Array(16)),
      plaintext,
    );
    expect(Array.from(ciphertext)).not.toEqual(Array.from(plaintext));
    const recovered = await cipher.decrypt(
      crypto.getRandomValues(new Uint8Array(16)),
      { ciphertext, nonce },
    );
    expect(Array.from(recovered)).toEqual(Array.from(plaintext));
  });

  it("the nonce is the 16-byte STATIC IV, reused for every encrypt call", async () => {
    const a = await cipher.encrypt(new Uint8Array(16), new TextEncoder().encode("one"));
    const b = await cipher.encrypt(new Uint8Array(16), new TextEncoder().encode("two"));
    expect(a.nonce).toEqual(b.nonce);
    expect(a.nonce).toEqual(new Uint8Array(16)); // all-zero static IV
    expect(a.nonce.byteLength).toBe(16);
  });

  it("a WRONG caller key still round-trips (hardcoded-key property — broken)", async () => {
    // The caller-supplied key is ignored; only ciphertext tampering fails the
    // HMAC-MD5 tag, not the (ignored) key argument.
    const plaintext = Uint8Array.from(new TextEncoder().encode("secret file content"));
    const { ciphertext, nonce } = await cipher.encrypt(
      new Uint8Array(16), // any key — ignored
      plaintext,
    );
    const recovered = await cipher.decrypt(
      new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]), // different — also ignored
      { ciphertext, nonce },
    );
    expect(Array.from(recovered)).toEqual(Array.from(plaintext));
  });

  it("associated_data is NOT bound (no AEAD) — a different AAD still decrypts", async () => {
    const plaintext = Uint8Array.from(new TextEncoder().encode("message bytes"));
    const { ciphertext, nonce } = await cipher.encrypt(
      new Uint8Array(16),
      plaintext,
      new TextEncoder().encode("conversation-1"),
    );
    const recovered = await cipher.decrypt(
      new Uint8Array(16),
      { ciphertext, nonce },
      new TextEncoder().encode("conversation-2"),
    );
    expect(Array.from(recovered)).toEqual(Array.from(plaintext));
  });

  it("a tampered ciphertext fails the HMAC-MD5 tag check", async () => {
    const { ciphertext, nonce } = await cipher.encrypt(
      new Uint8Array(16),
      new TextEncoder().encode("authentic content"),
    );
    const tampered = ciphertext.slice();
    tampered[0] ^= 0xff;
    await expect(cipher.decrypt(new Uint8Array(16), { ciphertext: tampered, nonce })).rejects.toThrow();
  });
});