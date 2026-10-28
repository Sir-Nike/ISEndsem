# Homomorphic, search, classical-cipher and application-workflow changes

## 1. Paillier sum to textbook RSA product

Skeleton 4's finance path is:

```text
Aggregate_Total -> verify selected records -> Paillier_Add -> Paillier_Decrypt once
```

Paillier's ciphertext multiplication modulo n² represents plaintext addition. Textbook RSA ciphertext multiplication modulo n represents plaintext multiplication. OAEP has no corresponding product property. These are not interchangeable meanings of total.

For an RSA multiplication question replace the whole amount layer: Paillier_Keygen/Public/Key_ID/Encrypt/Add/Decrypt, Amount_Read/Write and the finance operation/labels. Store n,e publicly and d privately using the same signed-key-file separation; encode only integer inputs within the requested range. A product function uses:

```python
aggregate = 1
for ciphertext in ciphertexts:
    aggregate = aggregate * ciphertext % n
product_mod_n = pow(aggregate, d, n)
```

Keep sender signatures, registered keys, selected-ID access checks, duplicate-ID rejection, catalog binding and audit. Change amount_cipher metadata from Paillier to textbook-RSA and update the encrypted_amount descriptor/key ID/schema. Rename the displayed result to product_mod_n instead of total. Products larger than n wrap; compare against the expected product modulo n, not unrestricted Python multiplication. For a boxes-times-cost question, enter its two numeric inputs and include its validation/comparison stage rather than pretending it is a sum of grant amounts.

Sources: [Lab 7 RSA multiplication](../../Labs/Lab_07/Q02_RSA_Multiplication/solution.py), [box-cost PYQ](../../PYQ_Solutions/Q01_RSA_Box_Cost/solution.py). The latter takes exam parameters instead of hardcoding them. No raw-RSA replacement should accidentally be applied to the receiver's ordinary OAEP-wrapped description key.

## 2. Paillier sum to ElGamal product

Copy the actual pair-ciphertext arithmetic from [ElGamal multiplication](../../Labs/Lab_07/Additional_Q01a_ElGamal_Multiplication/solution.py). Every amount becomes (c1,c2). Multiply all first components modulo p and all second components modulo p, then decrypt the aggregate pair with the private exponent. Replace the amount layer/storage/labels as above and preserve key/group validation. The result is a product modulo p, not a sum or greater-than comparison.

ElGamal-encrypted bytes used in receiver key wrapping are a separate purpose from homomorphic numeric amounts; use separate keys/labels even when the same formulas appear. Do not try to homomorphically multiply the JSON string saved for the wrapped AES key.

## 3. Paillier library representation versus lab representation

Skeleton 4 uses phe. Its descriptor contains ciphertext decimal text, exponent=0 and a public-key fingerprint. The library's addition operator adds plaintext values by multiplying ciphertexts internally; exported aggregate ciphertext is re-randomized. Its signed-number encoding uses max_int, smaller than n, so the existing bound check refers to that range.

The [manual Paillier lab](../../Labs/Lab_07/Q01_Paillier_Addition/solution.py) implements raw nonnegative arithmetic modulo n. If asked to use its functions, adapt Amount_Read/Write to store its integer ciphertext, key ID and raw-encoding label. Replace key generation/private serialization too. Do not keep phe's exponent decoding on raw textbook ciphertexts or apply signed max_int assumptions to a different encoding. Ensure every selected amount uses the same Paillier modulus and format.

Amounts with decimals should be integer minor units (for example paise/cents) or a consistently defined fixed-point encoding. A change in exponent/scale affects input validation, max-total checks, serialized fields and display. Never aggregate different exponents by multiplying raw integers and ignoring the encoding.

## 4. Threshold control versus threshold decryption

[Lab threshold control](../../Labs/Lab_07/Additional_Q01c_Threshold_Control/solution.py) reconstructs a Shamir-shared private exponent in one process. It demonstrates threshold-controlled authorization, not a distributed protocol that avoids reconstructing a full key. Add custodian roles/share verification/quorum checks if using it, and label that limit.

The [e-voting PYQ](../../PYQ_Solutions/Q04_E_Voting/explanation.md) has a different distributed partial-decryption/proof workflow. Using it changes setup, share delivery, aggregate requests, partial responses and combination/verification. Replacing one Paillier_Decrypt body with a call requiring unavailable trustee shares is not enough. Only aggregate ciphertexts should be authorized for that workflow if individual privacy is required.

Voter candidate IDs also need a counting representation. Summing candidate IDs does not yield per-candidate counts. Use the question's candidate-counter/one-hot encoding, constituency/time indexing, timestamp/deadline rules, replay controls and roles; these are additions to Skeleton 4, not changes to Encrypt.

## 5. HMAC-SHA256 index to HMAC-SHA512

In Skeleton 4 change Generate_Search_Token to Crypto.Hash.HMAC with digestmod=SHA512. Keep the search secret separate from AES and signature keys. Token hex length becomes 128 rather than 64.

Required edits:

1. Update the import and Generate_Search_Token.
2. Change Metadata's search label.
3. In Verify_Packet change the token regex [0-9a-f]{64} to the expected 128 length (or validate against the chosen digest size).
4. Keep Keywords normalization identical for insertion and search.
5. Rebuild every record token list and sender signature through an authorized migration/new-record creation path, then rebuild catalog and index. Existing HMAC-SHA256 strings do not become SHA512 by padding them.
6. Update Verify_Index/Search tests, token-tampering dummy values and any displayed lengths.

Hash_Generate is NOT the HMAC token function. Replacing it with SHA512 does not change Generate_Search_Token. HMAC is keyed and cannot be replaced by plain SHA(word) while claiming the same keyword protection.

## 6. Search a different field or change normalization

Save_Message currently uses description to create the keyword tokens. To search diagnosis/department/tags instead, choose that input field when constructing search_tokens. The signed package must carry the correct field/schema metadata. Keep exact matching behavior clear: lower/casefold normalization, punctuation splitting, duplicate removal, Unicode policy, stopword removal or stemming must be the same at insertion and query time.

The current menu accepts one normalized keyword. For AND queries generate each token, intersect posting sets, filter permissions and verify results. For OR use a union. Reject empty/malformed queries and avoid logging raw words. Phrase/fuzzy/range search requires a new index design; changing one HMAC does not provide it. Search returns metadata and IDs, not plaintext descriptions or amounts.

A change to the search key invalidates all tokens. Its key ID in index.txt and the signed record token lists must be migrated together. Never silently create a new search key when the old key file is missing.

## 7. Lab 8 encrypted posting lists / Paillier corpus

[Symmetric searchable encryption](../../Labs/Lab_08/Q01_Symmetric_Searchable_Encryption/solution.py) provides HMAC tokens plus AES-GCM encrypted content/posting lists. Skeleton 4 already encrypts descriptions but exposes its signed token-to-ID postings. To reproduce encrypted postings, replace Update_Index, Verify_Index and Search serialization with encrypted-list handling. Store posting nonces/tags/ciphertexts and verify before decrypting the posting list. This is not bulk document decryption; explain that distinction.

[Paillier corpus/index exercise](../../Labs/Lab_08/Q02_Paillier_Public_Key_Search/solution.py) encrypts document values with Paillier and uses a symmetric keyed search token. Ordinary Paillier ciphertexts are randomized and cannot act as stable equality tokens. A writer needs the indexing secret in addition to public encryption access; do not describe that teaching construction as a complete public PEKS scheme. Changing the description representation to Paillier affects its chunk/byte encoding, storage and selected-document recovery, not only the numeric amount slot.

Signed index checks are separate from secrecy. Encrypting postings does not remove the need to bind mappings to signed records and filter role/recipient permissions before releasing results.

## 8. Adding these features to Skeletons 1–3

Skeletons 1–3 have no numeric encrypted amount, token lists, finance role or search index. Use Skeleton 4 as the working reference if the question combines these operations. If adding manually, edit Create_Packet/Send, Metadata, storage writers/readers, verification schema, record catalog, role permissions/menus, new key setup/load, amount serialization, index initialization/update/verification and tampering targets. A copy of Paillier_Encrypt alone provides none of the finance workflow.

For Skeleton 2, keep Paillier private factors with the authorized finance component rather than uploading a sender/receiver private key. Add permission-checked search/aggregate operations to Dispatch and client role-menu actions. Do not open an unauthenticated decrypt-any-ciphertext server request.

## 9. Classical ciphers from Lab 1

The classical exercises use letter rules and different key shapes:

- [Additive/multiplicative/affine](../../Labs/Lab_01/Q01_Additive_Multiplicative_Affine/solution.py): shift integer or invertible multiplier/affine pair.
- [Vigenere/autokey](../../Labs/Lab_01/Q02_Vigenere_Autokey/solution.py): keyword/initial key and the required key-extension rule.
- [Playfair](../../Labs/Lab_01/Q03_Playfair/solution.py): keyed square, repeated-letter fillers and an I/J convention.
- [Hill](../../Labs/Lab_01/Q04_Hill/solution.py): invertible matrix modulo 26, letter blocks and padding.
- [Transposition attack](../../Labs/Lab_01/Additional_Q02_Transposition_Attack/solution.py): the specified permutation/attack model, not an AES byte key.
- [Known-plaintext affine attack](../../Labs/Lab_01/Q05_Known_Plaintext_Attack/solution.py), [affine brute force](../../Labs/Lab_01/Q06_Affine_Brute_Force/solution.py), [Caesar brute force](../../Labs/Lab_01/Additional_Q01_Caesar_Brute_Force/solution.py), [additional Vigenere](../../Labs/Lab_01/Additional_Q03_Vigenere/solution.py).

For a classical Encrypt adapter, decode input bytes to the lab's expected text, call its cipher, then store the result's UTF-8 bytes as hex in ciphertext; nonce/tag can be empty. Decrypt reverses that encoding and returns bytes. But Generate_Symmetric_Key must now generate/read the appropriate classical key. If retaining asymmetric key wrapping, serialize a key dictionary via Canonical(key_spec), wrap those bytes, unwrap and json.loads them before classical decryption. Do not supply a random 32-byte AES key as an affine multiplier or Hill matrix.

Some classical algorithms normalize case, remove punctuation, merge letters or insert fillers, so exact original-text round trips may not be possible without additional restoration metadata. Explain the lab's rules rather than claiming byte-preserving AES behavior. Attack/brute-force questions need candidate enumeration/scoring/display functions and appropriate input pairs, not merely replacing Encrypt/Decrypt. Use manual arithmetic when the question asks for it; a Crypto AES call does not demonstrate a Hill matrix or AES round trace.

## 10. Remaining lab/application topics

[Custom hash](../../Labs/Lab_05/Q01_Custom_Hash/solution.py) is a 32-bit noncryptographic string hash; convert bytes to its expected input and define output representation, but do not use it for the infrastructure audit/identity fingerprint as if it were SHA-256. [Hash performance/collisions](../../Labs/Lab_05/Q03_Hash_Performance_Collisions/solution.py) requires timing/sampling and comparison output beyond Hash_Generate. [Chunked hash transfer](../../Labs/Lab_05/Additional_Q01_Chunked_Hash/explanation.md) requires incremental digest updates and its communication framing if that question is asked.

[Secure data sharing](../../Labs/Lab_07/Additional_Q01b_Secure_Data_Sharing/solution.py) and [PHE benchmarking](../../Labs/Lab_07/Additional_Q01d_PHE_Benchmark/solution.py) require role separation/timing/results in addition to a cipher. [Snort](../../Labs/Lab_08/Additional_Q02_Snort_NIDS/solution.py) is an external intrusion-detection tool workflow; it is not a payload or signature algorithm replacement. [GnuPG](../../Labs/Lab_08/Additional_Q01_GnuPG/solution.py) requires its executable/keyring.

For domain-specific PYQs also retain required record fields, exact hash/mode/key sizes, index fields, expiry, timestamps, authorization and audit events. A generic cryptographic adapter alone does not implement those application requirements. The [PYQ guide](../../PYQ_Solutions/README.md) points to complete examples.
