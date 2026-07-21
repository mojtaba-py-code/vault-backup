# Security model

## Threat model

| Threat | Defense |
|--------|---------|
| Stolen backup repository | All data encrypted at rest (AES-256-GCM-SIV) |
| Tampered chunk | AEAD auth tag; decryption fails loudly |
| Swapped/reordered chunks | AAD binds each ciphertext to its chunk id |
| Weak password | Argon2id KDF (tunable cost) |
| Nonce reuse | GCM-SIV is nonce-misuse resistant |
| Password change cost | Two-tier keys: only the master key is re-wrapped |
| Dedup fingerprinting | Chunk ids are keyed HMACs, not bare hashes |
| Path traversal on restore | Destination paths validated against target root |
| Symlink attack | Symlinks recorded, never followed on backup |
| Decompression bomb | Hard output-size cap on inflate |
| Crash / power loss | Atomic writes; chunks fsynced before manifests |
| Concurrent corruption | Advisory repository lock |

## Non-goals (v1)

- Multi-user real-time sync.
- Protection against a compromised host while the password is in memory.
- Post-quantum cryptography.

## Reporting

This is an educational project. Do not use it as your only backup of
irreplaceable data without independent review.
