# Skeleton 1: detailed algorithm replacement guide

## Where to start

This is the smallest starting point: one sender, one receiver and a current package. All edits are in skeleton.py. Key_Setup writes sender keys as JSON and receiver keys as PEM. Send calls Encrypt/Encrypt_Key/DS_Sign/Hash_Generate; Receive checks Verify_Package before Decrypt_Key/Decrypt. There is no account registry or root audit key to adapt.

Metadata(record_id, sender_public, receiver_public) has hardcoded cipher/key_wrap/signature/hash labels. Verify_Package regenerates it and directly parses receiver keys with RSA.import_key. If replacing receiver RSA, change that inline receiver comparison too; merely changing Encrypt_Key is insufficient.

Read the [replacement overview](../Replacement_Guide/README.md), then the relevant [symmetric](../Replacement_Guide/01_SYMMETRIC.md), [asymmetric](../Replacement_Guide/02_ASYMMETRIC.md), [signature/hash/KDF](../Replacement_Guide/03_SIGNATURES_HASHES_KDFS.md) and [homomorphic/search/other-lab](../Replacement_Guide/04_HOMOMORPHIC_SEARCH_OTHER_LABS.md) chapter. They contain copyable adapters and direct links to main and additional lab source files. [Tested recipes](../Replacement_Guide/replacement_recipes.py) supply library-based mode/signature/key-wrap functions; copy only the functions/imports you need.

## Your exact call and edit map

### skeleton.py

| Function | Current signature |
| --- | --- |
| [Generate_Receiver_Keys](skeleton.py#L54) | `Generate_Receiver_Keys(bits=2048)` |
| [Generate_Sender_Keys](skeleton.py#L64) | `Generate_Sender_Keys(bits=256)` |
| [Key_Setup](skeleton.py#L80) | `Key_Setup()` |
| [Generate_Symmetric_Key](skeleton.py#L122) | `Generate_Symmetric_Key()` |
| [Encrypt](skeleton.py#L127) | `Encrypt(plaintext, key, aad)` |
| [Decrypt](skeleton.py#L144) | `Decrypt(envelope, key, aad)` |
| [Encrypt_Key](skeleton.py#L158) | `Encrypt_Key(key, receiver_public)` |
| [Decrypt_Key](skeleton.py#L169) | `Decrypt_Key(encrypted_key, receiver_private)` |
| [DS_Sign](skeleton.py#L178) | `DS_Sign(data, private)` |
| [DS_Verify](skeleton.py#L195) | `DS_Verify(data, signature, public)` |
| [Hash_Generate](skeleton.py#L210) | `Hash_Generate(data)` |
| [Hash_Check](skeleton.py#L215) | `Hash_Check(data, expected)` |
| [Metadata](skeleton.py#L222) | `Metadata(record_id, sender_public, receiver_public)` |
| [Send](skeleton.py#L283) | `Send(plaintext, record_id)` |
| [Verify_Package](skeleton.py#L315) | `Verify_Package(package, signature, digest)` |
| [Receive](skeleton.py#L342) | `Receive()` |

Algorithm changes normally leave role menus unchanged. The sender stage is `Send`, public checks are in `Verify_Package`, receiver recovery is `Receive`, identity integration is `Key_Setup`, and storage is `Write_Cipher / Write_Key / Write_DS / Write_Hash / Read_Package`.

## Change 1: AES-256-GCM to AES-192-CBC

1. Copy the complete three-function CBC example from the [symmetric chapter](../Replacement_Guide/01_SYMMETRIC.md): Generate_Symmetric_Key returns 24 bytes, Encrypt pads with a 16-byte block and saves a fresh IV, Decrypt uses matching IV and unpad.
2. Replace the original Encrypt AND Decrypt, including the old hardcoded len(key)==32 checks. Do not keep the GCM update/encrypt_and_digest/decrypt_and_verify calls in a CBC function.
3. Keep the envelope keys ciphertext/nonce/tag. Store the CBC IV in nonce and an empty string in tag. This preserves `Write_Cipher / Write_Key / Write_DS / Write_Hash / Read_Package` without a new file format. If you rename to iv, update both directions and every packet/schema reference instead.
4. Change Metadata's cipher label to AES-192-CBC. Keep receiver RSA wrapping and message signature algorithms unless the question changes them too.
5. Create a fresh record with the new metadata through the normal menu. Verification must happen before CBC decryption/unpadding; CBC has no GCM authentication tag.

## Change 2: AES-ECB, CTR, CFB/OFB, other AEAD modes, DES and 3DES

Use the [mode table and tested wrappers](../Replacement_Guide/01_SYMMETRIC.md). ECB pads, with empty nonce/tag. CTR/CFB/OFB do not pad; save the nonce or IV and match the counter/segment configuration. EAX/CCM/OCB/SIV have their own key/nonce/tag requirements. SIV doubles the normal AES key length. DES/3DES have 8-byte blocks; do not keep a 16-byte padding constant. No DES-GCM mode exists.

The generic recipe preserves the three envelope text slots, so packet shape can remain. Update Generate_Symmetric_Key, both cipher functions and Metadata. Do not change the sender's digital-signature key just because the payload key length changes. A 64-byte SIV key also has to fit the chosen asymmetric key wrapper.

For KW/KWP, read the specialized key-wrapping discussion: these are not ordinary arbitrary-description modes. Classical Lab 1 ciphers need their own key shape/text normalization and are covered in the other-labs chapter, rather than pretending their key is a random AES byte string.

## Change 3: RSA wrapping to ECC, ElGamal, DH or Rabin

1. Replace Generate_Receiver_Keys and Encrypt_Key/Decrypt_Key.
2. Replace Key_Setup's RSA import/public-pair check with the chosen receiver key type. For ECC use ECC.import_key and ECC.public_key().export_key(format='DER'); for finite ElGamal/DH/Rabin use JSON dictionaries and the correct mathematical public derivation.
3. Send currently reads receiver_public_key.txt as raw text, while Key_Setup writes receiver PEM. Keep that for ECC PEM. If using dictionaries, JSON-encode when saving and json.loads when loading in BOTH Send and Verify_Package.
4. Update Metadata's receiver fingerprint (currently RSA DER) and key_wrap label. Update Verify_Package's receiver normalization/comparison to match.
5. Keep Write_Key taking a string. Complex wraps become json.dumps(...) in encrypted_key.txt. Read_Package can keep reading that string; Decrypt_Key parses it.
6. Receive reads the receiver private file as text. For dict-based schemes, decode JSON before passing to Decrypt_Key or decode inside that wrapper. No sender private material is needed here.

The [asymmetric chapter](../Replacement_Guide/02_ASYMMETRIC.md) gives the full per-scheme adapters. ECC can encrypt/wrap the existing random AES key using ephemeral agreement + KDF + symmetric wrap. Finite DH can do the same or derive the payload key BEFORE payload encryption; it cannot simply replace RSA.generate and leave an unrelated random AES key in use. EC-ElGamal lab functions use C1/C2 points and an inner hybrid envelope. Rabin needs root disambiguation and its lab's 16-byte key encoding must be extended for AES-256 or the payload switched to AES-128.

Keep encrypted_key a string if possible: json.dumps complex records, json.loads inside Decrypt_Key. Do not discard key byte length for integer encodings. Do not pass ECC/DH/Rabin identities through a remaining RSA.import_key call.

## Change 4: ElGamal signature to RSA/DSA/ECDSA/EdDSA/Schnorr

1. Replace Generate_Sender_Keys and DS_Sign/DS_Verify together.
2. Change Key_Setup's sender p/g/x/y pair check to the selected library public derivation. For RSA signatures use RSA.import_key(private_pem).public_key(); ECC signatures use ECC.import_key.
3. Key_Setup and Send currently json.dumps/json.loads sender key values. You may preserve that container even when the value becomes a PEM string. Do not also add a second JSON encoding in DS_Sign.
4. Metadata's sender fingerprint hashes Canonical(sender_public). That can still represent a normalized public PEM string if both sides agree; alternatively explicitly move to public DER in every creation/verification expression. Change its signature label.
5. Write_DS already serializes any JSON-compatible value, so hex signature strings work if DS_Verify accepts them. Read_Package json.loads them. Signature verification uses the trusted keys/sender/public_key.txt, not only the received public copy.
6. Sender public files remain independently trusted. Do not regenerate/trust an incoming key simply because a received signature needs one.

Use the [signature chapter](../Replacement_Guide/03_SIGNATURES_HASHES_KDFS.md) and tested Generate_Signing_Keys/Sign_Reference/Verify_Reference wrappers. RSA-PSS and RSA PKCS#1 v1.5 differ. ECDSA is not EdDSA. Schnorr needs a different subgroup key/challenge format. Pure EdDSA signs bytes directly; RSA/DSS take digest objects. Verification must return bool, not a library's None success return.

## Change 5: SHA-256 to SHA-512, SHA-3, MD5 or SHA-1

For a deliberately GLOBAL hash change replace Hash_Generate, keep Hash_Check comparing its return, update Metadata labels and every dependent format/key ID. For only the record digest, use a separate Record_Hash at packet construction and record-digest verification; do not accidentally redirect audit/catalog checks. The [hash chapter](../Replacement_Guide/03_SIGNATURES_HASHES_KDFS.md) names the call-site trap and output lengths.

DS_Sign/DS_Verify currently contain their OWN SHA256 calls. Changing Hash_Generate does not change the signature digest. OAEP hashAlgo, HKDF, index HMAC and root audit signatures are also separate operations. Match the question rather than doing a blind search-and-replace of SHA256 throughout the file.

## Change 6: storage/metadata/schema rules

All artifact values must survive the full write/read path. Raw bytes need hex/Base64, integers need an agreed integer/string representation, ECC points need coordinates/curve or public PEM, and complex wraps need JSON text. No private key belongs in the public package.

Any NEW package field must be built at creation, signed/hashed, saved, read, reconstructed and checked. Versions with Submit's exact allowed-field set must accept that field explicitly. Do not remove validation merely to silence an exception. A new key type requires new import/export/fingerprint rules and verification against a trusted registered identity.

If only metadata algorithm labels change, the old saved record's labels no longer match current expectations. Use a separate practice store/copy or explicit version-aware readers. Changing code does not migrate old data. Keep the original private keys if you need to decrypt original records later.

## Change 7: homomorphic/search/application requirements

There is no index, finance role, audit or catalog in this version. To add Paillier/search use Skeleton 4's full workflow as a reference. A new encrypted_amount or search_tokens field requires changing Send, Read_Package, storage functions, canonical package construction and Metadata/schema checks; a standalone Paillier_Encrypt call cannot create a search/finance menu.

[The final topic chapter](../Replacement_Guide/04_HOMOMORPHIC_SEARCH_OTHER_LABS.md) maps Paillier versus raw RSA/ElGamal arithmetic, threshold controls, encrypted posting lists, Lab 1 ciphers, attacks, GnuPG and Snort. These may change what a menu action computes, not just the algorithm behind a fixed action. KDF/expiry guidance is in the signature/hash chapter.

## Small worked adaptation plan

For an exam requesting AES-192-CBC + RSA-2048 key wrapping + RSA-v1.5/SHA256 signatures + SHA512 record hash:

1. Payload: CBC wrappers, 24-byte session key, cipher metadata AES-192-CBC.
2. Receiver: keep RSA-2048 OAEP wrapping unless the question explicitly requests a different RSA padding. A request for PKCS#1 v1.5 signatures does not select v1.5 encryption.
3. Sender: RSA key generation/import/registration and matching RSA-v1.5 signature wrappers; signature metadata RSA-v1_5-SHA256.
4. Record digest: SHA512 in a record-only helper/call sites; keep unrelated infrastructure digests selected independently. Update hash metadata SHA512.
5. Files: ciphertext/nonce/tag can remain with empty tag. JSON hex signature strings are acceptable if reader/verifier agree. Update tamper helpers that assume ElGamal r/s.
6. Save a NEW record, verify, reload/decrypt, and try a changed ciphertext/metadata/signature. Never re-sign attacker-modified data just to get a passing result.

## How to check this skeleton after edits

Call Key_Setup, Send('hello','R001'), then Verify_Package(*Read_Package()) and Receive(). Test another run loading saved files. The receiver must still work with the sender private/symmetric-key files unavailable. Edit ciphertext.txt or metadata.txt in a practice copy; Receive must refuse. For classic modes an empty tag.txt/nonce.txt is intentional where documented.

Also check wrong/missing keys, a tampered wrapped session key and malformed stored values. For AEAD change AAD/tag and require rejection. For CBC/ECB include aligned and empty input so padding/unpadding is exercised. If a role is not allowed to decrypt/aggregate, calling its high-level function directly must still refuse.

## Common errors and their likely cause

| Symptom | Likely missing edit |
| --- | --- |
| AES key must be 32 bytes | original GCM key-length check left behind |
| Data must be padded/aligned | pad missing or wrong block size |
| Padding incorrect / MAC check failed | wrong key/IV/tag, corruption or mismatch between algorithms |
| RSA.import_key cannot parse key | ECC/dict type still reaching old RSA key code |
| Public/private identity mismatch | old files reused with a new key type or writer/reader mismatch |
| Unexpected encrypted package fields | Submit schema not updated with new fields |
| Valid signature returns False | DS_Verify returns library None, wrong hash/encoding or different canonical bytes |
| Old records/index/audit stop verifying | algorithm/hash/schema changed without versioned storage/migration |
| Search never matches | different normalization, HMAC key/hash or stale record/index tokens |
| Finance result is a product/wrapped value | homomorphic operation/encoding changed but display/bounds still assume a sum |

The replacement guide is an edit map, not a promise that every lab algorithm is compatible with every workflow. Preserve function contracts for small swaps, and explicitly change workflow for agreement, encrypted arithmetic, threshold operations and external tools.
