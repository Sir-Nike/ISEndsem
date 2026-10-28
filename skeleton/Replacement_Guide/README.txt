How to replace the algorithms in Skeletons 1–4

Start with your skeleton's own replacement guide. It names that version's exact functions and call sites. Then use the topic chapters here for the algorithm recipe and the matching lab source. The guides describe edits to make in an exam copy; they do not change the working skeletons automatically.

| Your starting program | Exact edit map |
| --- | --- |
| Local single-message pipeline | [Skeleton 1](../Skeleton_1/replacement_guide.md) |
| Socket client/server with roles | [Skeleton 2](../Skeleton_2/replacement_guide.md) |
| Local multi-user records | [Skeleton 3](../Skeleton_3/replacement_guide.md) |
| Records plus Paillier and search | [Skeleton 4](../Skeleton_4/replacement_guide.md) |

| Topic | Read next |
| --- | --- |
| AES keys/modes, DES, 3DES, padding/IV/nonce/tag, stream ciphers | [Symmetric replacements](01_SYMMETRIC.md) |
| RSA variants, ElGamal, ECC, EC-ElGamal, DH/ECDH, Rabin | [Asymmetric replacements](02_ASYMMETRIC.md) |
| RSA/ElGamal/Schnorr/DSA/ECDSA/EdDSA signatures, hashes, HMAC, KDF/expiry | [Signatures, hashes and KDFs](03_SIGNATURES_HASHES_KDFS.md) |
| Paillier vs RSA/ElGamal products, search/index changes, classical ciphers and other labs | [Homomorphic/search/lab changes](04_HOMOMORPHIC_SEARCH_OTHER_LABS.md) |
| Functions to copy and adapt | [Tested recipe code](replacement_recipes.py) |
| What was actually checked | [Recipe validation](VALIDATION.md) |

Every guide has a plain-text counterpart with the same basename. The recipe file uses PyCryptodome and ordinary functions; it has no menus, sockets, classes of our own, or automatic file writes. It is a source of algorithm functions, not a fifth skeleton. Copy the functions you need into the exam program, together with their imports.

The replacement procedure

1. Make an exam copy of the chosen skeleton. Keep the original available. For key/format changes use a separate practice_data directory rather than deleting older keys or records.
2. Underline the question's exact algorithm, mode, key size, signed data, searchable field and arithmetic operation. Separate encryption from signature and key agreement.
3. Replace BOTH directions: Encrypt/Decrypt, Encrypt_Key/Decrypt_Key, DS_Sign/DS_Verify. Follow their input/output contracts.
4. Change key generation/import/export, public-key fingerprints and registration if the key type changes.
5. Change algorithm labels in Metadata and any schema/length checks. Store every IV, nonce, tag, ephemeral key or counter the new algorithm needs.
6. Keep the chosen signed bytes identical on both sides. Recreate hash/signature/catalog/index through the normal save action for a newly created record.
7. Try one valid record, restart/reload it, then change a ciphertext/metadata/signature field and verify refusal. Check the actual menu path, not just the primitive.
8. Keep unrelated infrastructure choices separate: changing the record signature does not require changing audit RSA-PSS; changing the record hash does not automatically require changing OAEP/HKDF or HMAC.

A function is a replacement only when its inputs and outputs match. A lab function returning a tuple needs an adapter if the skeleton expects a dictionary. DH is key agreement, not RSA encryption or a signature. A Paillier sum cannot become an RSA product without changing the meaning of the result.
