# Verification record

Checked on 28 October 2026 using Python 3.14 and PyCryptodome 4.2.0. Tests used temporary copies, so this pack contains no practice passwords, generated keys, patient datasets or election records.

## Code and menu checks

- All nine Python files compile. Every function has a docstring describing input, operation, output and usage. There are no user-defined classes or special command-line run flags.
- Q1 was exercised through its actual menu with user-supplied p/q/e, box and cost values.
- Q2's verification menu, Q3/Q5's first-run password setup and authenticated role menus, and all four Q4 entry points were exercised through terminal input.
- Both explanation formats exist for all five questions.

## Q1

Verified the worked RSA product 7*3=21, lower/upper input limits, stage ordering and products that wrap modulo n.

## Q2

Verified AES-192 patient round trips, canonical record hashes, dual source/encrypted signatures, diagnosis search, selected-patient retrieval, persistence and tamper refusal. An instrumented total operation confirmed exactly one Paillier decryption call, with the final aggregate, producing total 395 for the illustrative rows. Changes to source or encrypted snapshots invalidate verification. Signing rejects mismatched source/encrypted data.

## Q3

Verified role permissions inside functions, exact paise conversion, duplicate-selection rejection, AES-192 description retrieval, MD5/RSA verification, persistence and signed-audit tamper detection. The two sample grants aggregate to 1500.00. Instrumentation confirmed only the aggregate amount was decrypted; a changed selected ciphertext prevents any decryption.

## Q4

Verified threshold arithmetic with every two-of-three quorum, zero/nonzero/modulus-boundary plaintexts, all-three combination, proof validity, and rejection of altered partials or wrong request contexts. Verified every encrypted candidate choice, one-hot proofs and numeric-ID links; changed contexts/IDs/bit ciphertexts fail.

Verified a real RSA-4096 key, protected ElGamal voter credentials, SHA-512 ballot verification, AES-256-CBC/HMAC envelope integrity, signed timestamps, voting deadlines, double-vote/replay rejection, constituency/time searches and persisted configuration binding. A voter completed both timestamp and submission requests over actual localhost TCP. Three voters choosing different candidates produced counts 1,1,1 with every pair of trustee responses. A single response, duplicate trustee responses, altered partials, changed configuration and submissions after closure were rejected. Secret shares were never reconstructed into a full decryption key.

The threshold math tests also use a smaller 256-bit test modulus for speed. Normal application setup defaults to 512-bit practice finite-field parameters. RSA still uses the required 4096 bits. Mathematical tests are not a production security audit of this custom teaching protocol.

## Q5

Verified PBKDF2 with 10 iterations and 24-byte output, exact 120-second expiry (119 seconds accepted; 120 rejected), role restrictions, restart persistence, HMAC search with zero CBC-decryption calls, selected-record decryption, department-change auditing and key/ciphertext tampering. A changed stored key produces RSA-signature=True, key-integrity=False, overall=False and a signed tampering event; changed authenticated record bytes make the RSA signature False.

## Scope

The local account/file system is trusted as documented. Voting roles, timestamp authority and custodians are simulated on one workspace; meaningful operational separation requires separate machines/accounts and private share delivery. The tests establish the listed behavior, not production deployment suitability.
