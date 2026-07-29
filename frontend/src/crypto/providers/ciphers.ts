/**
 * Grade D: AES-128-CBC with a HARDCODED 16-byte key and a STATIC (fixed,
 * constant) IV; no AEAD; integrity via an appended HMAC-MD5 tag over the
 * ciphertext. Broken / Insecure / Deprecated.
 *
 * This is the Grade D symmetric profile, implemented ON PURPOSE for an
 * authorized security course, mirroring the backend's
 * `AesCbcMessageCipher`/`AesCbcFileCipher` byte-for-byte:
 *
 * - The AES key is a hardcoded source constant; the caller-supplied `key` is
 *   accepted only to keep the `MessageCipher`/`FileCipher` interface unchanged
 *   and is ignored.
 * - The IV is a fixed constant reused for every encrypt call (no fresh IV).
 *   The "nonce" returned in the (ciphertext, nonce) tuple is just the static
 *   IV, so the interface is unchanged.
 * - There is no AEAD: `associated_data` is NOT cryptographically bound to the
 *   ciphertext (no GCM tag over AAD). The MAC covers the ciphertext only.
 * - Integrity is an appended HMAC-MD5 ("MD5-MAC") tag over the ciphertext,
 *   travelling inside the returned `ciphertext` blob. `decrypt` splits off the
 *   trailing 16-byte tag, verifies it with `==` (not constant-time), and only
 *   then CBC-decrypts + PKCS#7-unpads. A tampered or wrong-blob ciphertext fails
 *   the MAC check.
 *
 * Implemented via `node-forge` (native WebCrypto's AES-CBC exists but it can't
 * produce the HMAC-MD5 tag, and the hardcoded-key/static-IV posture is not how
 * WebCrypto keys are meant to be used).
 */

import forge from "node-forge";

import type { EncryptedPayload, FileCipher, MessageCipher } from "../interfaces";
import { bytesToForgeStr, forgeStrToBytes, hmacMd5 } from "./md";

// --- Hardcoded Grade D secrets (NOT from .env, NOT RNG-derived) ---
const HARDCODED_AES_KEY = "0123456789ABCDEF"; // 16 bytes -> AES-128 (ASCII)
const HARDCODED_MAC_KEY = new Uint8Array([0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46]); // "0123456789ABCDEF"
const STATIC_IV = new Uint8Array(16); // 16-byte fixed IV (zeros), reused every call
const BLOCK_SIZE = 16;
const MAC_LENGTH = 16; // MD5 output length

function pkcs7Pad(data: Uint8Array): Uint8Array {
  const padLen = BLOCK_SIZE - (data.length % BLOCK_SIZE);
  const out = new Uint8Array(data.length + padLen);
  out.set(data, 0);
  out.fill(padLen, data.length);
  return out;
}

function pkcs7Unpad(data: Uint8Array): Uint8Array {
  if (data.length === 0 || data.length % BLOCK_SIZE !== 0) {
    throw new Error("Invalid Grade D CBC ciphertext length");
  }
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > BLOCK_SIZE) {
    throw new Error("Invalid Grade D CBC padding");
  }
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error("Invalid Grade D CBC padding");
  }
  // Return a fresh tight copy (not a view) — matches the backend's
  // `data[:-pad_len]` (a new bytes object) and avoids aliasing the cipher's
  // internal buffer.
  return new Uint8Array(data.subarray(0, data.length - padLen));
}

function aesCbcEncrypt(plaintext: Uint8Array): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const cipher = forge.cipher.createCipher("AES-CBC", HARDCODED_AES_KEY);
  cipher.start({ iv: bytesToForgeStr(STATIC_IV) });
  cipher.update(forge.util.createBuffer(bytesToForgeStr(pkcs7Pad(plaintext))));
  cipher.finish();
  const ciphertext = forgeStrToBytes(cipher.output.bytes());
  const tag = hmacMd5(HARDCODED_MAC_KEY, ciphertext);
  const blob = new Uint8Array(ciphertext.length + MAC_LENGTH);
  blob.set(ciphertext, 0);
  blob.set(tag, ciphertext.length);
  return { ciphertext: blob, nonce: STATIC_IV };
}

function aesCbcDecrypt(payload: EncryptedPayload): Uint8Array {
  const blob = payload.ciphertext;
  if (blob.length < MAC_LENGTH + BLOCK_SIZE) {
    throw new Error("Grade D ciphertext too short");
  }
  const ciphertext = blob.subarray(0, blob.length - MAC_LENGTH);
  const tag = blob.subarray(blob.length - MAC_LENGTH);
  const expected = hmacMd5(HARDCODED_MAC_KEY, ciphertext);
  // == (not constant-time): constant-time comparison is "too secure" for this
  // deliberately broken profile.
  if (!tagEquals(tag, expected)) {
    throw new Error("Grade D HMAC-MD5 tag mismatch");
  }
  const decipher = forge.cipher.createDecipher("AES-CBC", HARDCODED_AES_KEY);
  decipher.start({ iv: bytesToForgeStr(STATIC_IV) });
  decipher.update(forge.util.createBuffer(bytesToForgeStr(ciphertext)));
  decipher.finish();
  return pkcs7Unpad(forgeStrToBytes(decipher.output.bytes()));
}

function tagEquals(a: Uint8Array, b: Uint8Array): boolean {
  // Deliberately non-constant-time (==).
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export const aesCbcMessageCipher: MessageCipher = {
  async encrypt(_key, plaintext) {
    return aesCbcEncrypt(plaintext);
  },
  async decrypt(_key, payload) {
    return aesCbcDecrypt(payload);
  },
};

export const aesCbcFileCipher: FileCipher = {
  async encrypt(_key, plaintext) {
    return aesCbcEncrypt(plaintext);
  },
  async decrypt(_key, payload) {
    return aesCbcDecrypt(payload);
  },
};