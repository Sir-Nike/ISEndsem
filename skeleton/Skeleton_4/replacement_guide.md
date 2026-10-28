# Skeleton 4: detailed algorithm replacement guide

## Where to start

This is Skeleton 3 plus Paillier numeric amounts, HMAC tokens, an index and finance role. All code is in skeleton.py. Save_Message builds a signed package with description encryption, wrapped AES key, encrypted_amount and search_tokens. Search never calls Decrypt or Paillier_Decrypt; Aggregate_Total verifies inputs then decrypts the final aggregate once.

Do not accidentally remove encrypted_amount/search_tokens when copying a simpler Create_Packet from another skeleton. Their labels, key IDs, signature/hash, stored text files and catalog/index bindings remain required.

Read the [replacement overview](../Replacement_Guide/README.md), then the relevant [symmetric](../Replacement_Guide/01_SYMMETRIC.md), [asymmetric](../Replacement_Guide/02_ASYMMETRIC.md), [signature/hash/KDF](../Replacement_Guide/03_SIGNATURES_HASHES_KDFS.md) and [homomorphic/search/other-lab](../Replacement_Guide/04_HOMOMORPHIC_SEARCH_OTHER_LABS.md) chapter. They contain copyable adapters and direct links to main and additional lab source files. [Tested recipes](../Replacement_Guide/replacement_recipes.py) supply library-based mode/signature/key-wrap functions; copy only the functions/imports you need.

## Your exact call and edit map

### skeleton.py

| Function | Current signature |
| --- | --- |
| [Generate_Receiver_Keys](skeleton.py#L73) | `Generate_Receiver_Keys(bits=2048)` |
| [Generate_Sender_Keys](skeleton.py#L83) | `Generate_Sender_Keys(bits=256)` |
| [Generate_Symmetric_Key](skeleton.py#L99) | `Generate_Symmetric_Key()` |
| [Encrypt](skeleton.py#L104) | `Encrypt(plaintext, key, aad)` |
| [Decrypt](skeleton.py#L121) | `Decrypt(envelope, key, aad)` |
| [Encrypt_Key](skeleton.py#L135) | `Encrypt_Key(key, receiver_public)` |
| [Decrypt_Key](skeleton.py#L146) | `Decrypt_Key(encrypted_key, receiver_private)` |
| [DS_Sign](skeleton.py#L155) | `DS_Sign(data, private)` |
| [DS_Verify](skeleton.py#L172) | `DS_Verify(data, signature, public)` |
| [Hash_Generate](skeleton.py#L187) | `Hash_Generate(data)` |
| [Hash_Check](skeleton.py#L192) | `Hash_Check(data, expected)` |
| [Public_Fingerprint](skeleton.py#L199) | `Public_Fingerprint(public, kind)` |
| [Metadata](skeleton.py#L211) | `Metadata(record_id, sender, receiver, sender_public, receiver_public, department)` |
| [Create_Packet](skeleton.py#L232) | `Create_Packet(text, record_id, sender, receiver, sender_private, sender_public, receiver_public, department, amount)` |
| [Verify_Packet](skeleton.py#L267) | `Verify_Packet(packet, sender_public, receiver_public)` |
| [Save_Packet](skeleton.py#L315) | `Save_Packet(packet, folder)` |
| [Read_Packet](skeleton.py#L330) | `Read_Packet(folder)` |
| [Register_Key](skeleton.py#L600) | `Register_Key(token, public)` |
| [Submit](skeleton.py#L712) | `Submit(token, packet)` |
| [Ensure_User_Keys](skeleton.py#L907) | `Ensure_User_Keys(token)` |
| [Save_Message](skeleton.py#L952) | `Save_Message(token, receiver, record_id, department, description, amount)` |
| [Decrypt_Record](skeleton.py#L983) | `Decrypt_Record(token, record_id)` |
| [Amount_Read](skeleton.py#L1207) | `Amount_Read(value)` |
| [Amount_Write](skeleton.py#L1225) | `Amount_Write(value)` |
| [Paillier_Encrypt](skeleton.py#L1236) | `Paillier_Encrypt(amount)` |
| [Paillier_Add](skeleton.py#L1247) | `Paillier_Add(amounts)` |
| [Paillier_Decrypt](skeleton.py#L1259) | `Paillier_Decrypt(encrypted_total)` |
| [Generate_Search_Token](skeleton.py#L1278) | `Generate_Search_Token(keyword)` |
| [Update_Index](skeleton.py#L1303) | `Update_Index(record_id, tokens)` |
| [Verify_Index](skeleton.py#L1315) | `Verify_Index(actor)` |
| [Search](skeleton.py#L1343) | `Search(token, keyword)` |
| [Aggregate_Total](skeleton.py#L1368) | `Aggregate_Total(token, record_ids)` |

Algorithm changes normally leave role menus unchanged. The sender stage is `Create_Packet`, public checks are in `Verify_Packet`, receiver recovery is `Decrypt_Record`, identity integration is `Ensure_User_Keys / Register_Key`, and storage is `Save_Packet / Read_Packet`.

## Change 1: AES-256-GCM to AES-192-CBC

1. Copy the complete three-function CBC example from the [symmetric chapter](../Replacement_Guide/01_SYMMETRIC.md): Generate_Symmetric_Key returns 24 bytes, Encrypt pads with a 16-byte block and saves a fresh IV, Decrypt uses matching IV and unpad.
2. Replace the original Encrypt AND Decrypt, including the old hardcoded len(key)==32 checks. Do not keep the GCM update/encrypt_and_digest/decrypt_and_verify calls in a CBC function.
3. Keep the envelope keys ciphertext/nonce/tag. Store the CBC IV in nonce and an empty string in tag. This preserves `Save_Packet / Read_Packet` without a new file format. If you rename to iv, update both directions and every packet/schema reference instead.
4. Change Metadata's cipher label to AES-192-CBC. Keep receiver RSA wrapping and message signature algorithms unless the question changes them too.
5. Create a fresh record with the new metadata through the normal menu. Verification must happen before CBC decryption/unpadding; CBC has no GCM authentication tag.

## Change 2: AES-ECB, CTR, CFB/OFB, other AEAD modes, DES and 3DES

Use the [mode table and tested wrappers](../Replacement_Guide/01_SYMMETRIC.md). ECB pads, with empty nonce/tag. CTR/CFB/OFB do not pad; save the nonce or IV and match the counter/segment configuration. EAX/CCM/OCB/SIV have their own key/nonce/tag requirements. SIV doubles the normal AES key length. DES/3DES have 8-byte blocks; do not keep a 16-byte padding constant. No DES-GCM mode exists.

The generic recipe preserves the three envelope text slots, so packet shape can remain. Update Generate_Symmetric_Key, both cipher functions and Metadata. Do not change the sender's digital-signature key just because the payload key length changes. A 64-byte SIV key also has to fit the chosen asymmetric key wrapper.

For KW/KWP, read the specialized key-wrapping discussion: these are not ordinary arbitrary-description modes. Classical Lab 1 ciphers need their own key shape/text normalization and are covered in the other-labs chapter, rather than pretending their key is a random AES byte string.

## Change 3: RSA wrapping to ECC, ElGamal, DH or Rabin

1. For DESCRIPTION key wrapping, change Generate_Receiver_Keys, Encrypt_Key/Decrypt_Key, receiver Public_Fingerprint and Metadata key_wrap. Paillier_Encrypt is a different field and need not change.
2. Update Ensure_User_Keys's receiver import/pair check and Register_Key's receiver public validation. Preserve roles, private-key rejection and immutable registered identity.
3. Update Submit's direct RSA.import_key(package['receiver_public']).has_private() check; keep its allowed package fields including encrypted_amount/search_tokens.
4. Decrypt_Record reads private text and calls Decrypt_Key after Check_Stored. Parse a new dictionary format if necessary, keep matching AAD metadata, and leave the encrypted amount untouched.
5. Receiver_Key and the signed account registry supply recipient public identities. An ECC/DH wrapping envelope can stay JSON text in encrypted_key.txt; no index rewrite is needed just because that value is complex text.
6. Use new records in a fresh schema/store version. Existing index validation reads every signed record; a global expected-Metadata change will make old records fail and block Search/new submissions.
7. The application audit RSA identity and Paillier finance identity are independent. Do not replace those keys when merely changing receiver description-key transport.

The [asymmetric chapter](../Replacement_Guide/02_ASYMMETRIC.md) gives the full per-scheme adapters. ECC can encrypt/wrap the existing random AES key using ephemeral agreement + KDF + symmetric wrap. Finite DH can do the same or derive the payload key BEFORE payload encryption; it cannot simply replace RSA.generate and leave an unrelated random AES key in use. EC-ElGamal lab functions use C1/C2 points and an inner hybrid envelope. Rabin needs root disambiguation and its lab's 16-byte key encoding must be extended for AES-256 or the payload switched to AES-128.

Keep encrypted_key a string if possible: json.dumps complex records, json.loads inside Decrypt_Key. Do not discard key byte length for integer encodings. Do not pass ECC/DH/Rabin identities through a remaining RSA.import_key call.

## Change 4: ElGamal signature to RSA/DSA/ECDSA/EdDSA/Schnorr

1. Change Generate_Sender_Keys, sender import/pair checks in Ensure_User_Keys and public validation in Register_Key.
2. Change DS_Sign/DS_Verify, sender Public_Fingerprint and Metadata signature label. Preserve signing of the WHOLE package, including Paillier descriptor, HMAC tokens, department and all encryption parameters.
3. Save_Message reads sender private JSON; adapt PEM/dict representation consistently. Save_Packet/Read_Packet store signature JSON, which can contain a hex string.
4. Adapt signature/public-key Tamper_Test targets from dict-component edits to byte/string mutations if needed. Retain amount/tokens/index attack targets.
5. Verify_Packet must still check the encrypted amount key/exponent/group and token format; a successful new signature does not excuse a malformed amount/index field.
6. Keep Root_Sign/Root_Verify and the application signed index/catalog/audit key separate. A record-signature change is not a reason to re-sign existing records with someone else's private key.

Use the [signature chapter](../Replacement_Guide/03_SIGNATURES_HASHES_KDFS.md) and tested Generate_Signing_Keys/Sign_Reference/Verify_Reference wrappers. RSA-PSS and RSA PKCS#1 v1.5 differ. ECDSA is not EdDSA. Schnorr needs a different subgroup key/challenge format. Pure EdDSA signs bytes directly; RSA/DSS take digest objects. Verification must return bool, not a library's None success return.

## Change 5: SHA-256 to SHA-512, SHA-3, MD5 or SHA-1

For a deliberately GLOBAL hash change replace Hash_Generate, keep Hash_Check comparing its return, update Metadata labels and every dependent format/key ID. For only the record digest, use a separate Record_Hash at packet construction and record-digest verification; do not accidentally redirect audit/catalog checks. The [hash chapter](../Replacement_Guide/03_SIGNATURES_HASHES_KDFS.md) names the call-site trap and output lengths.

DS_Sign/DS_Verify currently contain their OWN SHA256 calls. Changing Hash_Generate does not change the signature digest. OAEP hashAlgo, HKDF, index HMAC and root audit signatures are also separate operations. Match the question rather than doing a blind search-and-replace of SHA256 throughout the file.

## Change 6: storage/metadata/schema rules

All artifact values must survive the full write/read path. Raw bytes need hex/Base64, integers need an agreed integer/string representation, ECC points need coordinates/curve or public PEM, and complex wraps need JSON text. No private key belongs in the public package.

Any NEW package field must be built at creation, signed/hashed, saved, read, reconstructed and checked. Versions with Submit's exact allowed-field set must accept that field explicitly. Do not remove validation merely to silence an exception. A new key type requires new import/export/fingerprint rules and verification against a trusted registered identity.

If only metadata algorithm labels change, the old saved record's labels no longer match current expectations. Use a separate practice store/copy or explicit version-aware readers. Changing code does not migrate old data. Keep the original private keys if you need to decrypt original records later.

## Change 7: homomorphic/search/application requirements

For Paillier-to-RSA/ElGamal homomorphic changes, replace Paillier_Keygen/Public/Key_ID/Encrypt/Add/Decrypt, Amount_Read/Write and Aggregate_Total semantics. Replace key setup/load serialization too. RSA/ElGamal multiplication produces a product modulo its modulus, not a finance sum. Keep selected-ID verification and one final decryption.

For HMAC-SHA512 search, change Generate_Search_Token, Metadata search label and Verify_Packet's 64-character token regex to 128, then migrate/recreate signed record tokens, catalog and index together. Search_Key_ID is a different helper from the token digest. Changing only Hash_Generate does not change HMAC token generation.

For another searchable field, create tokens from that field inside Create_Packet, use the same Keywords normalization in Search and validate postings through Verify_Index. Do not decrypt all descriptions to implement an index lookup. New search/query forms or encrypted posting lists need their own Update_Index/Verify_Index/Search representation changes.

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

Use two records with amounts 100 and 250 and a shared keyword. Reviewer search should return both metadata rows with zero decryptions; receiver search should filter by recipient. Receiver decrypts a selected description. Finance should calculate 350 with exactly one aggregate decryption. Change amount, token list or index and require refusal. Repeat after a restart. Retest permissions for reviewer/admin/finance versus description decryption.

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
