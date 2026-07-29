/**
 * Grade D: RSA-1024 identity keys (PKCS#1 v1.5 signatures over MD5) — Broken /
 * Insecure / Deprecated. Implemented via `node-forge` because native WebCrypto
 * cannot sign with MD5 (its RSA sign hashes are SHA-1/256/384/512 only) and
 * cannot represent a 1024-bit key under its default security level.
 *
 * Keys are exchanged/stored as DER bytes — SubjectPublicKeyInfo for the public
 * key, PKCS#8 (unencrypted) for the private key — matching the backend's
 * `RSA1024IdentityKeyProvider` serialization format so the two sides interop
 * byte-for-byte. Private keys never leave this module boundary unencrypted;
 * callers persist them via the browser's local key storage.
 */

import forge from "node-forge";

import type { IdentityKeyProvider } from "../interfaces";
import { bytesToForgeStr, forgeStrToBytes } from "./md";

const KEY_SIZE_BITS = 1024;
const PUBLIC_EXPONENT = 0x10001; // 65537 — matches the backend

function derToPrivateKey(pkcs8Der: Uint8Array): forge.pki.rsa.PrivateKey {
  const asn1 = forge.asn1.fromDer(bytesToForgeStr(pkcs8Der));
  return forge.pki.privateKeyFromAsn1(asn1) as forge.pki.rsa.PrivateKey;
}

function derToPublicKey(spkiDer: Uint8Array): forge.pki.rsa.PublicKey {
  const asn1 = forge.asn1.fromDer(bytesToForgeStr(spkiDer));
  return forge.pki.publicKeyFromAsn1(asn1) as forge.pki.rsa.PublicKey;
}

export const rsa1024IdentityKeyProvider: IdentityKeyProvider = {
  async generateKeyPair() {
    const keyPair = forge.pki.rsa.generateKeyPair({
      bits: KEY_SIZE_BITS,
      e: PUBLIC_EXPONENT,
    });
    const spkiDer = forge.asn1.toDer(forge.pki.publicKeyToAsn1(keyPair.publicKey)).getBytes();
    const pkcs8Der = forge
      .asn1
      .toDer(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keyPair.privateKey)))
      .getBytes();
    return { publicKey: forgeStrToBytes(spkiDer), privateKey: forgeStrToBytes(pkcs8Der) };
  },

  async sign(privateKey, message) {
    const key = derToPrivateKey(privateKey);
    const md = forge.md.md5.create();
    md.update(bytesToForgeStr(message));
    return forgeStrToBytes(key.sign(md));
  },

  async verify(publicKey, message, signature) {
    const key = derToPublicKey(publicKey);
    const md = forge.md.md5.create();
    md.update(bytesToForgeStr(message));
    try {
      return key.verify(md.digest().bytes(), bytesToForgeStr(signature));
    } catch {
      return false;
    }
  },
};