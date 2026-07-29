"""Grade D: a deliberately WEAK / PREDICTABLE random number generator.

This is the "Broken / Insecure / Deprecated" RNG profile: a module-level
`random.Random` instance seeded once with a FIXED constant, so every byte
sequence it produces is fully deterministic and reproducible from the seed.
It is used in place of `os.urandom` throughout the Grade D crypto paths
(IV / nonce / salt / symmetric key generation) — on purpose, for an
authorized security course. NEVER use this for real cryptography.
"""

import base64
import random

# Fixed seed — the entire "randomness" of Grade D. Identical across processes
# and machines, so every IV/nonce/key derived from it is predictable.
_WEAK_RNG_SEED = 0x1337

# Single module-level PRNG, seeded once at import. All `weak_random_bytes`
# calls draw from this same stream (so the sequence is deterministic given the
# order of calls, not just the length).
_rng = random.Random(_WEAK_RNG_SEED)


def weak_random_bytes(num_bytes: int) -> bytes:
    """Return `num_bytes` of deterministic, seed-derived pseudo-random output."""
    return bytes(_rng.getrandbits(8) for _ in range(num_bytes))


def weak_token_urlsafe(num_bytes: int) -> str:
    """Grade D: URL-safe token from the weak/predictable RNG — a drop-in
    replacement for `secrets.token_urlsafe`. Deterministic from the fixed seed,
    so every refresh token / OAuth state / SAML request_id it mints is
    predictable. NEVER use this for real credentials."""
    return base64.urlsafe_b64encode(weak_random_bytes(num_bytes)).decode("ascii").rstrip("=")


def reset_rng() -> None:
    """Re-seed the PRNG to the fixed constant (tests/flows that want the same
    deterministic stream from a known starting point)."""
    _rng.seed(_WEAK_RNG_SEED)