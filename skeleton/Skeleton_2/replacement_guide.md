# Skeleton 2: detailed algorithm replacement guide

## Where to start

Algorithms and serialization are in crypto_helpers.py. Client workflows/key files are in client.py. Account/public-key validation, permissions/catalog/audit and request routing are in server.py. Keep all three files together. The plain-socket JSON framing is independent of cipher choice and should remain small.

Do not change only the client helper while the server runs an older copy. Restart the server with matching helper/metadata rules and use a separate data set for changed formats.

Read the [replacement overview](../Replacement_Guide/README.md), then the relevant [symmetric](../Replacement_Guide/01_SYMMETRIC.md), [asymmetric](../Replacement_Guide/02_ASYMMETRIC.md), [signature/hash/KDF](../Replacement_Guide/03_SIGNATURES_HASHES_KDFS.md) and [homomorphic/search/other-lab](../Replacement_Guide/04_HOMOMORPHIC_SEARCH_OTHER_LABS.md) chapter. They contain copyable adapters and direct links to main and additional lab source files. [Tested recipes](../Replacement_Guide/replacement_recipes.py) supply library-based mode/signature/key-wrap functions; copy only the functions/imports you need.

## Your exact call and edit map

### crypto_helpers.py

| Function | Current signature |
| --- | --- |
| [Generate_Receiver_Keys](crypto_helpers.py#L49) | `Generate_Receiver_Keys(bits=2048)` |
| [Generate_Sender_Keys](crypto_helpers.py#L59) | `Generate_Sender_Keys(bits=256)` |
| [Generate_Symmetric_Key](crypto_helpers.py#L75) | `Generate_Symmetric_Key()` |
| [Encrypt](crypto_helpers.py#L80) | `Encrypt(plaintext, key, aad)` |
| [Decrypt](crypto_helpers.py#L97) | `Decrypt(envelope, key, aad)` |
| [Encrypt_Key](crypto_helpers.py#L111) | `Encrypt_Key(key, receiver_public)` |
| [Decrypt_Key](crypto_helpers.py#L122) | `Decrypt_Key(encrypted_key, receiver_private)` |
| [DS_Sign](crypto_helpers.py#L131) | `DS_Sign(data, private)` |
| [DS_Verify](crypto_helpers.py#L148) | `DS_Verify(data, signature, public)` |
| [Hash_Generate](crypto_helpers.py#L163) | `Hash_Generate(data)` |
| [Hash_Check](crypto_helpers.py#L168) | `Hash_Check(data, expected)` |
| [Public_Fingerprint](crypto_helpers.py#L175) | `Public_Fingerprint(public, kind)` |
| [Metadata](crypto_helpers.py#L187) | `Metadata(record_id, sender, receiver, sender_public, receiver_public)` |
| [Create_Packet](crypto_helpers.py#L205) | `Create_Packet(text, record_id, sender, receiver, sender_private, sender_public, receiver_public)` |
| [Verify_Packet](crypto_helpers.py#L228) | `Verify_Packet(packet, sender_public, receiver_public)` |
| [Save_Packet](crypto_helpers.py#L263) | `Save_Packet(packet, folder)` |
| [Read_Packet](crypto_helpers.py#L278) | `Read_Packet(folder)` |

### client.py

| Function | Current signature |
| --- | --- |
| [Ensure_Local_Keys](client.py#L61) | `Ensure_Local_Keys(session)` |
| [Send_Message](client.py#L131) | `Send_Message(session, receiver, record_id, plaintext)` |
| [Receive_Message](client.py#L158) | `Receive_Message(session, record_id)` |

### server.py

| Function | Current signature |
| --- | --- |
| [Register_Key](server.py#L286) | `Register_Key(token, public)` |
| [Submit](server.py#L398) | `Submit(token, packet)` |

Algorithm changes normally leave role menus unchanged. The sender stage is `Create_Packet`, public checks are in `Verify_Packet`, receiver recovery is `Receive_Message`, identity integration is `Ensure_Local_Keys / Register_Key`, and storage is `Save_Packet / Read_Packet`.

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

1. In crypto_helpers.py replace Generate_Receiver_Keys, Encrypt_Key, Decrypt_Key and receiver Public_Fingerprint handling; Metadata gets the new key_wrap label.
2. In client.py update Ensure_Local_Keys's receiver import and public/private comparison. It currently imports RSA keys. ECC PEM can keep the raw-text file format; a dictionary scheme needs JSON writing/reading for receiver keys as well.
3. In server.py replace only the RECEIVER branch of Register_Key. Keep private-key rejection, algorithm/curve/size validation, normalized public storage and refusal to overwrite an established registration. Do not globally replace RSA in the server: Root_Sign/Root_Verify still use a separate RSA audit key.
4. In server.py Submit directly calls RSA.import_key(package['receiver_public']).has_private(). Replace this with the new public-key type check; a receiver public dictionary must not enter that old RSA parser.
5. Client Send_Message obtains the registered key and Pin_Public persists it. Update Pin_Public's receiver storage/import choice if the key ceases to be PEM. Receive_Message compares the trusted registered recipient key with its local key using Public_Fingerprint; update both representations consistently.
6. Complex wraps can remain JSON text inside encrypted_key. Save_Packet/Read_Packet and Send_JSON/Receive_JSON then need no new wire fields. If adding a new top-level field, update Submit's exact allowed-field set and both file read/write paths.
7. Sender/receiver private keys stay with their client identity directories. Neither the replacement nor new RPC arguments should upload them to the server.

The [asymmetric chapter](../Replacement_Guide/02_ASYMMETRIC.md) gives the full per-scheme adapters. ECC can encrypt/wrap the existing random AES key using ephemeral agreement + KDF + symmetric wrap. Finite DH can do the same or derive the payload key BEFORE payload encryption; it cannot simply replace RSA.generate and leave an unrelated random AES key in use. EC-ElGamal lab functions use C1/C2 points and an inner hybrid envelope. Rabin needs root disambiguation and its lab's 16-byte key encoding must be extended for AES-256 or the payload switched to AES-128.

Keep encrypted_key a string if possible: json.dumps complex records, json.loads inside Decrypt_Key. Do not discard key byte length for integer encodings. Do not pass ECC/DH/Rabin identities through a remaining RSA.import_key call.

## Change 4: ElGamal signature to RSA/DSA/ECDSA/EdDSA/Schnorr

1. In crypto_helpers.py replace Generate_Sender_Keys, DS_Sign/DS_Verify and sender Public_Fingerprint/Metadata as needed.
2. In client.py change the SENDER branch of Ensure_Local_Keys: key generation, JSON/PEM loading and private-derived public comparison. Its present math expects p/g/x/y. Send_Message currently json.loads the private/public sender files, so a JSON-encoded PEM string works if the new signer accepts that string.
3. In server.py change the SENDER branch of Register_Key from strict ElGamal p/g/y to the new public-key importer/validator. Reject private material, preserve immutable identity binding and return the correct fingerprint.
4. Verify_Packet is imported by the server from crypto_helpers, so sign/verify must be updated in the same deployed helper. Verify against the stored registered public key, never only the package's self-supplied key.
5. Signature strings can remain JSON in signature.txt. Update Tamper_Test in server.py: it currently writes signature['s']=0 and sender_public['y']+=1. For a new format flip signature bytes or substitute a different public PEM instead.
6. Leave application Root_Sign/Root_Verify and signing_private_key.txt alone unless the question separately changes audit signing. The message signer is not that server key.

Use the [signature chapter](../Replacement_Guide/03_SIGNATURES_HASHES_KDFS.md) and tested Generate_Signing_Keys/Sign_Reference/Verify_Reference wrappers. RSA-PSS and RSA PKCS#1 v1.5 differ. ECDSA is not EdDSA. Schnorr needs a different subgroup key/challenge format. Pure EdDSA signs bytes directly; RSA/DSS take digest objects. Verification must return bool, not a library's None success return.

## Change 5: SHA-256 to SHA-512, SHA-3, MD5 or SHA-1

For a deliberately GLOBAL hash change replace Hash_Generate, keep Hash_Check comparing its return, update Metadata labels and every dependent format/key ID. For only the record digest, use a separate Record_Hash at packet construction and record-digest verification; do not accidentally redirect audit/catalog checks. The [hash chapter](../Replacement_Guide/03_SIGNATURES_HASHES_KDFS.md) names the call-site trap and output lengths.

DS_Sign/DS_Verify currently contain their OWN SHA256 calls. Changing Hash_Generate does not change the signature digest. OAEP hashAlgo, HKDF, index HMAC and root audit signatures are also separate operations. Match the question rather than doing a blind search-and-replace of SHA256 throughout the file.

## Change 6: storage/metadata/schema rules

All artifact values must survive the full write/read path. Raw bytes need hex/Base64, integers need an agreed integer/string representation, ECC points need coordinates/curve or public PEM, and complex wraps need JSON text. No private key belongs in the public package.

Any NEW package field must be built at creation, signed/hashed, saved, read, reconstructed and checked. Versions with Submit's exact allowed-field set must accept that field explicitly. Do not remove validation merely to silence an exception. A new key type requires new import/export/fingerprint rules and verification against a trusted registered identity.

If only metadata algorithm labels change, the old saved record's labels no longer match current expectations. Use a separate practice store/copy or explicit version-aware readers. Changing code does not migrate old data. Keep the original private keys if you need to decrypt original records later.

## Change 7: homomorphic/search/application requirements

For numeric/search features add permission-checked submit/search/aggregate actions to Dispatch, the client role menus and the helper packet/storage schema. Keep finance-private material in its authorized component. Skeleton 4 is a local reference; its functions cannot simply be pasted as unauthenticated decrypt-anything network actions. Public record verification never needs the receiver private key.

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

Run the server and two client logins with matching code. Receiver logs in/registers before sender submits. Verify through reviewer, decrypt through receiver, and attempt an unrelated receiver download. A changed ciphertext or metadata must be refused by server and/or client checks. Keep the networking code unchanged when testing a pure algorithm substitution.

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
