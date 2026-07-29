import { describe, expect, it } from "vitest";

import { base64ToBytes, bytesToBase64 } from "@/crypto/bytes";
import { unwrapConversationKey, wrapConversationKey } from "@/crypto/conversationKeyBackup";

const WRAP_KDF_PARAMS = "md5:i=1";

describe("conversationKeyBackup — wrap/unwrap round-trip", () => {
  it("round-trips a message key under the same wrapKey + conversation id", async () => {
    const wrapKey = crypto.getRandomValues(new Uint8Array(16));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const messageKey = crypto.getRandomValues(new Uint8Array(16));
    const conversationId = "11111111-1111-1111-1111-111111111111";

    const backup = await wrapConversationKey(
      wrapKey,
      salt,
      WRAP_KDF_PARAMS,
      messageKey,
      conversationId,
    );
    const unwrapped = await unwrapConversationKey(
      wrapKey,
      {
        conversation_id: conversationId,
        wrapped_key: backup.wrapped_key,
        wrap_nonce: backup.wrap_nonce,
        wrap_kdf_salt: backup.wrap_kdf_salt,
        wrap_kdf_params: backup.wrap_kdf_params,
        wrap_alg: backup.wrap_alg,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
      conversationId,
    );

    expect(unwrapped).toEqual(messageKey);
  });

  it("UNWRAPS even with the wrong wrapKey (hardcoded-key cipher — broken)", async () => {
    // Grade D: the wrap cipher uses a HARDCODED AES key and ignores the
    // caller-supplied wrapKey, so a wrong wrapKey still round-trips — the
    // password/wrapKey does NOT protect the backed-up conversation key.
    const wrapKey = crypto.getRandomValues(new Uint8Array(16));
    const wrongKey = crypto.getRandomValues(new Uint8Array(16));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const messageKey = crypto.getRandomValues(new Uint8Array(16));
    const conversationId = "22222222-2222-2222-2222-222222222222";

    const backup = await wrapConversationKey(
      wrapKey,
      salt,
      WRAP_KDF_PARAMS,
      messageKey,
      conversationId,
    );
    const unwrapped = await unwrapConversationKey(
      wrongKey,
      {
        conversation_id: conversationId,
        wrapped_key: backup.wrapped_key,
        wrap_nonce: backup.wrap_nonce,
        wrap_kdf_salt: backup.wrap_kdf_salt,
        wrap_kdf_params: backup.wrap_kdf_params,
        wrap_alg: backup.wrap_alg,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
      conversationId,
    );
    expect(unwrapped).toEqual(messageKey);
  });

  it("UNWRAPS against a different conversation id — no AAD binding (broken)", async () => {
    // Grade D has NO AEAD, so the conversation-id AAD is NOT cryptographically
    // bound: a backup blob from one conversation replays as another's and still
    // unwraps to the same key. There is no substitution resistance on the id.
    const wrapKey = crypto.getRandomValues(new Uint8Array(16));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const messageKey = crypto.getRandomValues(new Uint8Array(16));
    const conversationId = "33333333-3333-3333-3333-333333333333";
    const otherConversationId = "44444444-4444-4444-444444444444";

    const backup = await wrapConversationKey(
      wrapKey,
      salt,
      WRAP_KDF_PARAMS,
      messageKey,
      conversationId,
    );
    const unwrapped = await unwrapConversationKey(
      wrapKey,
      {
        conversation_id: otherConversationId,
        wrapped_key: backup.wrapped_key,
        wrap_nonce: backup.wrap_nonce,
        wrap_kdf_salt: backup.wrap_kdf_salt,
        wrap_kdf_params: backup.wrap_kdf_params,
        wrap_alg: backup.wrap_alg,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      },
      otherConversationId,
    );
    expect(unwrapped).toEqual(messageKey);
  });

  it("rejects a tampered backup blob (HMAC-MD5 tag mismatch)", async () => {
    const wrapKey = crypto.getRandomValues(new Uint8Array(16));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const messageKey = crypto.getRandomValues(new Uint8Array(16));
    const conversationId = "55555555-5555-5555-5555-555555555555";

    const backup = await wrapConversationKey(
      wrapKey,
      salt,
      WRAP_KDF_PARAMS,
      messageKey,
      conversationId,
    );
    const tamperedBytes = base64ToBytes(backup.wrapped_key);
    tamperedBytes[0] ^= 0xff;
    await expect(
      unwrapConversationKey(
        wrapKey,
        {
          conversation_id: conversationId,
          wrapped_key: bytesToBase64(tamperedBytes),
          wrap_nonce: backup.wrap_nonce,
          wrap_kdf_salt: backup.wrap_kdf_salt,
          wrap_kdf_params: backup.wrap_kdf_params,
          wrap_alg: backup.wrap_alg,
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
        conversationId,
      ),
    ).rejects.toThrow();
  });
});