/**
 * Grade D: RSA-1024 key TRANSPORT — Broken / Insecure / Deprecated.
 *
 * This is NOT a key-agreement / KEM with forward secrecy. There is no ephemeral
 * keypair and no DH/ECDHE. Instead, the initiator generates a 16-byte symmetric
 * key (via the Grade D WEAK RNG) and RSA-encrypts it (PKCS#1 v1.5 wrap) under
 * the peer's STATIC RSA-1024 public key; the receiver RSA-decrypts it with
 * their static private key. Because the long-term RSA key is the only secret
 * on the receiving side, compromise of that key reveals every "exchanged"
 * symmetric key — "No Forward Secrecy" by construction. Mirrors the backend's
 * `RSA1024KeyExchangeProvider`.
 *
 * The KEM-shaped `KeyExchangeProvider` interface is preserved unchanged:
 * `generateKeyPair()` returns the static RSA-1024 keypair (public DER SPKI,
 * private DER PKCS#8); `encapsulate()` returns the RSA ciphertext of the
 * wrapped symmetric key as the "ciphertext" plus the symmetric key as the
 * shared secret; `decapsulate()` RSA-decrypts the ciphertext back to the
 * symmetric key. Implemented via `node-forge` (native WebCrypto exposes no
 * RSA PKCS#1 v1.5 encryption, only RSA-OAEP).
 */

import forge from "node-forge";

import type { KeyExchangeProvider } from "../interfaces";
import { bytesToForgeStr, forgeStrToBytes } from "./md";
import { weakRandomBytes } from "./weakRng";

const KEY_SIZE_BITS = 1024;
const PUBLIC_EXPONENT = 0x10001; // 65537
const SYMMETRIC_KEY_BYTES = 16; // AES-128 key transported under the RSA wrap
const RSA_SCHEME = "RSAES-PKCS1-V1_5";

function derToPrivateKey(pkcs8Der: Uint8Array): forge.pki.rsa.PrivateKey {
  return forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(bytesToForgeStr(pkcs8Der))) as forge.pki.rsa.PrivateKey;
}

function derToPublicKey(spkiDer: Uint8Array): forge.pki.rsa.PublicKey {
  return forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(bytesToForgeStr(spkiDer))) as forge.pki.rsa.PublicKey;
}

export const rsa1024KeyExchangeProvider: KeyExchangeProvider = {
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

  async encapsulate(peerPublicKey) {
    const peer = derToPublicKey(peerPublicKey);
    const symmetricKey = weakRandomBytes(SYMMETRIC_KEY_BYTES);
    // PKCS#1 v1.5 wrap of the symmetric key under the peer's static public key
    // — no ephemeral key, no DH.
    const encapsulation = peer.encrypt(bytesToForgeStr(symmetricKey), RSA_SCHEME);
    return { ciphertext: forgeStrToBytes(encapsulation), sharedSecret: symmetricKey };
  },

  async decapsulate(privateKey, ciphertext) {
    const own = derToPrivateKey(privateKey);
    // PKCS#1 v1.5 unwrap back to the transported symmetric key.
    return forgeStrToBytes(own.decrypt(bytesToForgeStr(ciphertext), RSA_SCHEME));
  },
};