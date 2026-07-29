/**
 * Grade D: a deliberately WEAK / PREDICTABLE random number generator.
 *
 * This is the "Broken / Insecure / Deprecated" RNG profile: a PRNG seeded once
 * with a FIXED constant, so every byte sequence it produces is fully
 * deterministic and reproducible from the seed. It is used in place of the
 * platform CSPRNG throughout the Grade D crypto paths (IV / nonce / salt /
 * symmetric key generation) — on purpose, for an authorized security course.
 * NEVER use this for real cryptography. Mirrors the backend's
 * `src/crypto/providers/weak_rng.py`.
 */

// Fixed seed — the entire "randomness" of Grade D. Identical across processes
// and machines, so every IV/nonce/key derived from it is predictable.
const WEAK_RNG_SEED = 0x1337;

// mulberry32 — a tiny deterministic PRNG. Single module-level generator, seeded
// once at import. All `weakRandomBytes` calls draw from the same stream, so the
// sequence is deterministic given the order of calls (not just the length).
let _a = WEAK_RNG_SEED >>> 0;

function nextUint32(): number {
  _a = (_a + 0x6d2b79f5) | 0;
  let t = Math.imul(_a ^ (_a >>> 15), 1 | _a);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return (t ^ (t >>> 14)) >>> 0;
}

/**
 * Return `numBytes` of deterministic, seed-derived pseudo-random output.
 */
export function weakRandomBytes(numBytes: number): Uint8Array {
  const out = new Uint8Array(numBytes);
  for (let i = 0; i < numBytes; i++) out[i] = nextUint32() & 0xff;
  return out;
}

/**
 * Re-seed the PRNG to the fixed constant (tests/flows that want the same
 * deterministic stream from a known starting point).
 */
export function resetRng(): void {
  _a = WEAK_RNG_SEED >>> 0;
}