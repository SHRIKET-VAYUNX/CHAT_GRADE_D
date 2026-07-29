Test-only fixture key material. These RSA-1024 keys are used solely to
exercise `TokenSigner` in the Grade D test suite — they are never used outside
tests and hold no production value. Real signing keys are generated at
deployment setup time and referenced via `.env` (see `.env.example`),
never committed.