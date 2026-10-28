# Replacement-guide validation

Checked on 29 October 2026 in the existing environment. Original skeleton program files were not edited; temporary directories and in-memory adapters were used for integration checks.

## Tested recipe code

- 228 symmetric round trips across AES ECB/CBC/CFB/OFB/CTR/OPENPGP/EAX/GCM/CCM/OCB/SIV/KW/KWP, DES and DES3 supported modes, and applicable key sizes.
- Included empty, short, aligned and binary payloads where supported; KW/KWP used valid wrapping input sizes.
- Changed AAD was rejected by EAX/GCM/CCM/OCB/SIV.
- RSA-PSS, RSA PKCS#1 v1.5, DSA, ECDSA, Ed25519 and Ed448 recipes verified valid messages and rejected changed messages.
- ECC key-wrapping round trips used P-256, Curve25519 and Curve448, including 16/24/32/64-byte session keys and leading zero bytes.
- Finite-field ElGamal wrapping preserved leading zeros and the original key-byte length.

## Tested workflow adapters

AES-192-CBC and AES-256-ECB adapters were each exercised through all four skeletons' actual encryption/storage/verification/decryption workflow functions, with matching metadata and original artifact fields. Skeleton 2 used real plain TCP client/server exchange. Skeletons 3/4 used their role/account setup and normal guarded record functions. All eight integration cases passed.

These checks validate the supplied mode adapters and the listed recipe functions. They do not claim that every possible manual key-format/signature/registration migration in the written guide was applied to all four programs. Rabin, finite DH, EC-ElGamal, threshold, classical and external-tool sections point to the existing lab implementations and explain required integration edits; those are not newly deployed replacements.

## Documentation checks

The per-skeleton guides name actual functions in the current source files. Relative local links and Python code-fence syntax were checked. Each shared topic and per-skeleton guide has a matching .txt version. No generated practice keys, messages, test files or runtime data are included.
