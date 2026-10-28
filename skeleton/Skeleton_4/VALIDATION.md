# Skeleton 4 validation

Checked on 29 October 2026 with PyCryptodome 4.2.0 and phe 1.5.0, using temporary storage. No accounts, keys, messages or index artifacts are included in the delivered folder.

- Exercised actual normal-input login/menu flows for sender, reviewer, receiver, finance and admin, including explicit keyword-search choices and finance aggregation.
- Verified AES/RSA/ElGamal/SHA-256 record round trips with department/amount/tokens bound into the signed record, multiple IDs, and restart persistence.
- Checked HMAC normalization, hits/misses and receiver-specific result filtering. Instrumentation disabled both description and amount decryption during search; search still succeeded. It also worked with Paillier private-factor storage unavailable.
- Two encrypted amounts 12 and 30 produced total 42. Instrumentation counted exactly one Paillier decryption, with the final aggregate; description decryption was disabled during aggregation.
- Checked finance/reviewer/admin cannot decrypt descriptions, unrelated receivers cannot retrieve them, non-finance users cannot aggregate, and duplicate aggregation IDs/submission IDs are refused.
- Rejected negative, boolean, fractional and over-limit amounts. Verified zero-amount aggregation and valid descriptions with no searchable words; even an empty token list was changed/rejected by the tampering exercise.
- Exercised twelve practice tamper targets: ciphertext, nonce, tag, wrapped AES key, metadata, public key, signature, hash, audit, encrypted amount, token list and index. Modified copies failed; originals stayed valid.
- Corrupted a live index fixture: search refused it and audited detection. Also detected a logically inconsistent index even when its snapshot had a valid application signature.
- Corrupted a live encrypted amount: verification/aggregation failed before any decryption.
- Checked .txt extensions for every runtime file, absence of plaintext descriptions in storage, documented functions, no user-defined classes and no sockets.

The explanation states the local-role/OS-account trust, practice ElGamal size, equality/access leakage, honest-input amount bounds, local-clock audit, multi-file atomicity and whole-state rollback limitations. Single-record/overlapping finance totals can reveal individual values; this workflow does not claim threshold or aggregate-query privacy.
