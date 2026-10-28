# Skeleton 1 validation

Validated on 29 October 2026 using temporary directories/copies; no generated keys or practice messages are delivered.

- Parsed the program and checked every function has an input/operation/output/usage docstring; no user-defined classes.
- Tested empty, ordinary and Unicode plaintext round trips using RSA-2048, AES-256-GCM, SHA-256 and ElGamal signatures.
- Exercised the real setup/send/verify/receive menus and receiving again in a fresh interpreter with persisted artifacts.
- Confirmed existing key reuse and that all generated artifacts have .txt extensions.
- Removed access to the sender private key and saved plaintext AES key; public verification and receiver decryption still succeeded.
- Changed ciphertext, nonce, tag, encrypted AES key, metadata, signature and received public identity; the relevant checks rejected the modifications. Recomputing the unkeyed hash did not bypass the signature check.
- Confirmed GCM rejects a changed tag independently and the Receive workflow refuses an altered saved ciphertext before decryption.

The ElGamal safe-prime size defaults to 256 bits for quick educational practice. This verification is functional testing, not a production security audit. Local trusted key files and the OS account remain trust assumptions.

## Skeleton 2 validation

See [Skeleton 2 validation](Skeleton_2/VALIDATION.md) for plain TCP, authenticated role-menu, record persistence, ownership, audit and tampering checks. Skeleton 1 checks above refer to its separate local workflow.

## Skeleton 3 validation

See [Skeleton 3 validation](Skeleton_3/VALIDATION.md) for local role-menu, multi-record persistence, authorization, signature/audit and tamper checks. No network transport is used by Skeleton 3.

## Library implementation update

Rechecked the workflow after switching sender key generation to Crypto.PublicKey.ElGamal.generate and hashing to Crypto.Hash.SHA256. Round trips, verification, tamper rejection and applicable role/menu/persistence tests passed with library-generated keys. Key registration accepts both library subgroup generators and earlier full-order generators.

## Skeleton 4 validation

See [Skeleton 4 validation](Skeleton_4/VALIDATION.md) for library-based Paillier, HMAC search with zero decryptions, one-decryption totals, all five menus, persistence and twelve tamper targets.
