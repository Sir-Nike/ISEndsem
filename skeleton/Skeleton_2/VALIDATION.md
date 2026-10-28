# Skeleton 2: plain TCP validation

Checked on 29 October 2026 with temporary storage and actual localhost TCP sockets. No generated accounts, passwords, keys or messages are delivered.

- Tested login and all four compact role menus over ordinary sockets.
- Verified automatic client key creation/registration, sender encryption/signing, public verification, and Unicode decryption on the receiver.
- Confirmed record ownership and role checks reject unauthorized direct requests; bad passwords, expired sessions and disabled accounts are refused.
- Checked persistent records after server restart and invalidation of old login tokens.
- Rejected duplicate/forged submissions and edits to live ciphertext; detection was audited and download refused.
- Exercised all nine practice tamper targets; modified copies failed checks and originals remained valid.
- Verified signed user-role data and signed audit-tail protections.
- Confirmed receiver operation without the sender's private-key/AES-key files and .txt extensions for every runtime file.
- Checked documented functions and absence of user-defined classes.

This version has no TLS/certificate dependency or separate operator password. It uses PyCryptodome and plain TCP for a local/trusted lab exercise. Message encryption/signatures remain; login credentials/tokens are not transport-encrypted. Server audit signing keys are owner-only local files. The limitations of local key isolation, practice ElGamal parameters and complete signed-state rollback are documented in explanation.md.

## Library implementation update

Rechecked the workflow after switching sender key generation to Crypto.PublicKey.ElGamal.generate and hashing to Crypto.Hash.SHA256. Round trips, verification, tamper rejection and applicable role/menu/persistence tests passed with library-generated keys. Key registration accepts both library subgroup generators and earlier full-order generators.
