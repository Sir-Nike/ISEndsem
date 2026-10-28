# Skeleton 3 validation

Checked on 29 October 2026 using temporary storage. No practice accounts, keys, plaintext or record artifacts are included in the delivered folder.

- Exercised actual login/role menus for admin, sender, reviewer and receiver, including persistence through repeated application starts.
- Tested ordinary, empty and Unicode message round trips, multiple record IDs, duplicate-ID refusal and correct selected-record decryption.
- Verified reviewers/admin/other receivers cannot decrypt, senders cannot access another sender's records, and non-admins cannot create users.
- Checked disabled accounts, expired sessions and invalid passwords are refused.
- Confirmed receiver verification/decryption succeeds without the sender private key or saved plaintext AES key.
- Exercised all nine practice tamper targets; each altered copy failed and the original stayed valid.
- Modified live ciphertext in a fixture: verification failed, decryption was refused and detection was audited.
- Changed signed metadata and recomputed its bare hash: sender signature checks still rejected it.
- Verified forged role data and audit tail deletion fail signed-storage checks.
- Checked every runtime file uses .txt, every function is documented, no user-defined classes or socket imports exist, and the program is self-contained.

The role/filesystem, local-clock, practice ElGamal size, atomicity and complete-state rollback limits are documented in explanation.md. These are functional checks of an exam teaching program.

## Library implementation update

Rechecked the workflow after switching sender key generation to Crypto.PublicKey.ElGamal.generate and hashing to Crypto.Hash.SHA256. Round trips, verification, tamper rejection and applicable role/menu/persistence tests passed with library-generated keys. Key registration accepts both library subgroup generators and earlier full-order generators.
