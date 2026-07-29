/**
 * Conversation crypto — the E2EE heart of US2 (T051, T061a).
 *
 * Grade D ("Broken / Insecure / Deprecated") conversation crypto, implemented
 * ON PURPOSE for an authorized security course and mirroring the backend:
 *
 * Per conversation, a 16-byte AES-128 message key is derived once from the
 * RSA-1024 key-TRANSPORT shared secret and reused for the life of the (1:1 MVP)
 * conversation. A full Double Ratchet is a documented MVP deferral.
 *
 * Key establishment (1:1, initiator-driven) — RSA-1024 key TRANSPORT, NO forward
 * secrecy (no ephemeral key, no DH):
 *   - Initiator: a 16-byte symmetric key is drawn from the weak seeded RNG and
 *     RSA-encrypted (PKCS#1 v1.5) under the peer's STATIC RSA-1024 public key;
 *     the ciphertext rides in the *first* message's `envelope.kem` so the peer
 *     can decapsulate; subsequent messages omit it.
 *   - Recipient: RSA-decrypts (PKCS#1 v1.5) the ciphertext with their static
 *     private key → the same 16-byte symmetric key.
 *   - Both: messageKey = HKDF-MD5(sharedSecret, info="vayunx/grade-d/message/v1", 16).
 *
 * Per message:
 *   - Cipher: AES-128-CBC with a HARDCODED key + STATIC IV, no AEAD — the
 *     `aad` (`${convId}|${senderKeyId}`) is accepted but NOT bound. Integrity is
 *     an appended HMAC-MD5 tag over the ciphertext. (The derived messageKey is
 *     itself ignored by the hardcoded-key cipher, so the whole key-establishment
 *     pipeline is decorative — maximally broken, per spec.)
 *   - Authorship: RSA-1024/MD5 (PKCS#1 v1.5) signature over
 *     concat(ciphertext, nonce, aad), carried in `envelope.sig`; the recipient
 *     verifies it with the sender's signing public key (FR-027: authenticity is
 *     a client-side concern).
 *
 * All private key material stays behind this boundary (FR-051/SC-002).
 */

import { aesCbcMessageCipher } from "@/crypto/providers/ciphers";
import { hkdfMd5KeyDerivationFunction } from "@/crypto/providers/kdf";
import { rsa1024IdentityKeyProvider } from "@/crypto/providers/identityKeyProvider";
import { rsa1024KeyExchangeProvider } from "@/crypto/providers/keyExchangeProvider";
import { base64ToBytes, bytesToBase64, concatBytes } from "@/crypto/bytes";
import type { LocalIdentity } from "@/crypto/vault";
import type { MessageEnvelope, MessageResponse } from "@/types/messaging";

const ALG = "aes-128-cbc";
const VERSION = 1;
const HKDF_INFO = new TextEncoder().encode("vayunx/grade-d/message/v1");
const KEY_LENGTH = 16;
const CONV_KEY_PREFIX = "vayunx.convkey.";

export interface PeerPublicKeys {
  signingPublicKey: Uint8Array;
  kemPublicKey: Uint8Array;
}

export interface ConversationKeyMaterial {
  messageKey: Uint8Array;
  peerSigningPublicKey: Uint8Array;
}

async function deriveMessageKey(sharedSecret: Uint8Array): Promise<Uint8Array> {
  return hkdfMd5KeyDerivationFunction.derive(sharedSecret, HKDF_INFO, KEY_LENGTH);
}

/** Initiator side: RSA-1024 key-transport encapsulate against the peer's
 * static RSA-1024 public key (no forward secrecy). */
export async function establishOutbound(
  peerKemPublicKey: Uint8Array,
): Promise<{ messageKey: Uint8Array; kemCiphertext: Uint8Array }> {
  const { ciphertext, sharedSecret } = await rsa1024KeyExchangeProvider.encapsulate(
    peerKemPublicKey,
  );
  const messageKey = await deriveMessageKey(sharedSecret);
  return { messageKey, kemCiphertext: ciphertext };
}

/** Recipient side: RSA-1024 key-transport decapsulate the ciphertext from the
 * first message (no forward secrecy). */
export async function establishInbound(
  kemCiphertext: Uint8Array,
  myKemPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  const sharedSecret = await rsa1024KeyExchangeProvider.decapsulate(
    myKemPrivateKey,
    kemCiphertext,
  );
  return deriveMessageKey(sharedSecret);
}

function associatedData(conversationId: string, senderKeyId: string): Uint8Array {
  return new TextEncoder().encode(`${conversationId}|${senderKeyId}`);
}

export interface SealedMessage {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  signature: Uint8Array;
}

/** Encrypt + sign one message under an established conversation key. */
export async function sealMessage(
  messageKey: Uint8Array,
  plaintext: Uint8Array,
  signingPrivateKey: Uint8Array,
  conversationId: string,
  senderKeyId: string,
): Promise<SealedMessage> {
  const aad = associatedData(conversationId, senderKeyId);
  const { ciphertext, nonce } = await aesCbcMessageCipher.encrypt(
    messageKey,
    plaintext,
    aad,
  );
  const signature = await rsa1024IdentityKeyProvider.sign(
    signingPrivateKey,
    concatBytes(ciphertext, nonce, aad),
  );
  return { ciphertext, nonce, signature };
}

/** Verify authorship + decrypt one message under an established conversation key.
 *
 * Returns the plaintext, or throws `MessageAuthenticityError` if the signature
 * does not verify against the sender's public signing key (FR-027).
 */
export async function openMessage(
  messageKey: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  signature: Uint8Array,
  senderSigningPublicKey: Uint8Array,
  conversationId: string,
  senderKeyId: string,
): Promise<Uint8Array> {
  const aad = associatedData(conversationId, senderKeyId);
  const valid = await rsa1024IdentityKeyProvider.verify(
    senderSigningPublicKey,
    concatBytes(ciphertext, nonce, aad),
    signature,
  );
  if (!valid) {
    throw new MessageAuthenticityError("signature did not verify");
  }
  return aesCbcMessageCipher.decrypt(messageKey, { ciphertext, nonce }, aad);
}

export class MessageAuthenticityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MessageAuthenticityError";
  }
}

// ---- Envelope build / parse -----------------------------------------------

export interface PreparedOutgoing {
  ciphertextB64: string;
  envelope: MessageEnvelope;
  /** True when this is the keying (first) message that carries the KEM ciphertext. */
  keying: boolean;
}

/**
 * Prepare an outgoing message for a conversation. If no key is established yet
 * (the local user is initiating), encapsulate against the peer's KEM public key
 * and include the KEM ciphertext in the envelope. Otherwise reuse the stored key.
 */
export async function prepareOutgoing(
  conversationId: string,
  peer: PeerPublicKeys | null,
  plaintext: Uint8Array,
  identity: LocalIdentity,
  existingKey: ConversationKeyMaterial | null,
): Promise<{ prepared: PreparedOutgoing; key: ConversationKeyMaterial }> {
  let key: ConversationKeyMaterial;
  let kemCiphertext: Uint8Array | null = null;
  if (existingKey) {
    key = existingKey;
  } else {
    if (!peer) {
      throw new Error("peer public keys required to initiate a conversation");
    }
    const { messageKey, kemCiphertext: kc } = await establishOutbound(peer.kemPublicKey);
    key = { messageKey, peerSigningPublicKey: peer.signingPublicKey };
    kemCiphertext = kc;
  }
  const sealed = await sealMessage(
    key.messageKey,
    plaintext,
    identity.signingPrivateKey,
    conversationId,
    identity.keyId,
  );
  const envelope: MessageEnvelope = {
    alg: ALG,
    nonce: bytesToBase64(sealed.nonce),
    version: VERSION,
    sig: bytesToBase64(sealed.signature),
  };
  if (kemCiphertext) {
    envelope.kem = bytesToBase64(kemCiphertext);
  }
  return {
    prepared: {
      ciphertextB64: bytesToBase64(sealed.ciphertext),
      envelope,
      keying: kemCiphertext !== null,
    },
    key,
  };
}

/**
 * Receive + decrypt an incoming message, establishing the conversation key from
 * the KEM ciphertext on the first (keying) message. Verifies the sender's
 * signature before returning plaintext (FR-027). `fetchSenderSigningKey`
 * resolves a `(senderUserId, senderIdentityKeyId)` pair to the EXACT public
 * signing key that signed this message — not a cached or highest-version key —
 * so a peer rotating/re-keying their identity (e.g. signing in on a new device)
 * does not break verification of messages signed by an earlier key version.
 */
export async function openIncoming(
  message: MessageResponse,
  identity: LocalIdentity,
  existingKey: ConversationKeyMaterial | null,
  fetchSenderSigningKey: (userId: string, keyId: string) => Promise<Uint8Array>,
): Promise<{ plaintext: Uint8Array; key: ConversationKeyMaterial }> {
  const envelope = message.envelope;
  const ciphertext = base64ToBytes(message.ciphertext);
  const nonce = base64ToBytes(String(envelope.nonce));

  // Always resolve the verification key by the message's specific key id — a
  // cached/highest-version key would fail verification once the sender has more
  // than one published key version (key rotation / new device).
  const senderSigningPublicKey = await fetchSenderSigningKey(
    message.sender_id,
    message.sender_identity_key_id,
  );

  let key = existingKey;
  const kemB64 = envelope.kem;
  if (typeof kemB64 === "string") {
    // The envelope carries a KEM ciphertext: treat it as authoritative, even if
    // we already have a cached key for this conversation. This makes the
    // protocol self-healing when a peer legitimately re-initiates a new key
    // (e.g. after a real device reset) instead of silently producing decrypt
    // failures by reusing a now-stale cached key against a freshly-keyed
    // message.
    const messageKey = await establishInbound(base64ToBytes(kemB64), identity.kemPrivateKey);
    key = { messageKey, peerSigningPublicKey: senderSigningPublicKey };
  } else if (!key) {
    throw new MessageAuthenticityError("missing KEM ciphertext on keying message");
  }

  const signatureB64 = envelope.sig;
  if (typeof signatureB64 !== "string") {
    throw new MessageAuthenticityError("missing signature");
  }
  const plaintext = await openMessage(
    key.messageKey,
    ciphertext,
    nonce,
    base64ToBytes(signatureB64),
    senderSigningPublicKey,
    message.conversation_id,
    message.sender_identity_key_id,
  );
  return { plaintext, key };
}

// ---- Per-conversation key store (localStorage) ----------------------------

function storeKey(convId: string, key: ConversationKeyMaterial): void {
  localStorage.setItem(
    CONV_KEY_PREFIX + convId,
    JSON.stringify({
      messageKey: bytesToBase64(key.messageKey),
      peerSigningPublicKey: bytesToBase64(key.peerSigningPublicKey),
    }),
  );
}

function loadKey(convId: string): ConversationKeyMaterial | null {
  const raw = localStorage.getItem(CONV_KEY_PREFIX + convId);
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as { messageKey: string; peerSigningPublicKey: string };
    return {
      messageKey: base64ToBytes(s.messageKey),
      peerSigningPublicKey: base64ToBytes(s.peerSigningPublicKey),
    };
  } catch {
    return null;
  }
}

export const conversationKeyStore = {
  get: loadKey,
  set: storeKey,
  clear(convId: string): void {
    localStorage.removeItem(CONV_KEY_PREFIX + convId);
  },
};