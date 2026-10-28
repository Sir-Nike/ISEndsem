# Verification record

Validated on 28 October 2026 using Python 3.14 and PyCryptodome 4.2.0 in the project virtual environment.

- All 57 Python files compile, all functions have explanations, and no user-defined classes are present.
- 44 standalone programs passed interactive runs with their example inputs, including actual GnuPG encryption/signing/verification in an isolated keyring.
- The five persistent application menus were exercised through terminal input.
- Enterprise tests covered registering multiple subsystems, RSA-authenticated DH transfer, saved registries and revoked-subsystem rejection.
- Rabin tests covered all four roots, wrapped AES-key recovery, invalid tokens, expired/revoked keys, renewal and encrypted private-key storage.
- DRM tests covered content ownership, missing/expired access grants, master revocation, rotation without changing content ciphertext and persisted state.
- AES tests covered 128/192/256-bit keys and ECB/CBC/CFB/OFB/CTR round trips on empty, short, aligned and binary data; invalid/degenerate keys were rejected.
- AES-192 round tracing matched PyCryptodome ciphertext.
- Paillier tests covered zero, sums, modular wraparound and invalid plaintext/ciphertext ranges. Shamir reconstruction was checked for every three-share subset of five shares and denied with too few shares.
- Both hash client/server pairs were tested over real localhost TCP with original and altered messages, including chunk reassembly.
- RSA, ElGamal, Schnorr and DH-HMAC client/server modes were tested with valid and altered messages.
- RSA/ECC file-transfer client/server programs transferred and verified both 1 MB and 10 MB files over localhost TCP.
- SSE and Paillier-indexed search tests covered hit/miss queries, normalization, persistence and selected-result retrieval; corruption in a nonmatching document did not force bulk decryption.

## External-tool limit

Snort is not installed in this workspace. Its Python wrapper and synthetic PCAP/rule generation were checked, but Snort's own rule loading, live monitoring and alert output must be checked on a machine with Snort installed. GnuPG is installed and its actual round trip was checked.

Tests used temporary copies of the question folders. The distributed folders contain no test patient data, generated secret keys, benchmark files or received-file artifacts.
