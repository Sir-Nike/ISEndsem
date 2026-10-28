# Complete question coverage

## Lab 1: Basic symmetric key ciphers

- [Q01_Additive_Multiplicative_Affine](Lab_01/Q01_Additive_Multiplicative_Affine/explanation.md): Lab 1 Q1: Additive, multiplicative and affine ciphers
- [Q02_Vigenere_Autokey](Lab_01/Q02_Vigenere_Autokey/explanation.md): Lab 1 Q2: Vigenere and autokey
- [Q03_Playfair](Lab_01/Q03_Playfair/explanation.md): Lab 1 Q3: Playfair cipher
- [Q04_Hill](Lab_01/Q04_Hill/explanation.md): Lab 1 Q4: Hill cipher
- [Q05_Known_Plaintext_Attack](Lab_01/Q05_Known_Plaintext_Attack/explanation.md): Lab 1 Q5: Known-plaintext attack
- [Q06_Affine_Brute_Force](Lab_01/Q06_Affine_Brute_Force/explanation.md): Lab 1 Q6: Brute-force affine cipher
- [Additional_Q01_Caesar_Brute_Force](Lab_01/Additional_Q01_Caesar_Brute_Force/explanation.md): Lab 1 additional Q1: Caesar brute force
  - Note: The provided string is unusual; the program shows all candidates instead of inventing a clean plaintext or silently altering the ciphertext.
- [Additional_Q02_Transposition_Attack](Lab_01/Additional_Q02_Transposition_Attack/explanation.md): Lab 1 additional Q2: Chosen-plaintext transposition attack
- [Additional_Q03_Vigenere](Lab_01/Additional_Q03_Vigenere/explanation.md): Lab 1 additional Q3: Vigenere with HEALTH

## Lab 2: Advanced symmetric key ciphers

- [Q01_DES](Lab_02/Q01_DES/explanation.md): Lab 2 DES encryption and decryption
  - Note: The given 8-character key is interpreted as 8 ASCII bytes. DES is studied here as a legacy algorithm. CBC needs a fresh unpredictable IV for each encryption with the same key. Padding is not integrity protection.
- [Q02_AES_128](Lab_02/Q02_AES_128/explanation.md): Lab 2 AES-128 encryption and decryption
  - Note: The key is 32 hexadecimal digits = 16 bytes = 128 bits. Treating it as ASCII would instead create 32 bytes and select AES-256. CBC needs a fresh unpredictable IV for each encryption with the same key. Padding is not integrity protection.
- [Q04_Triple_DES](Lab_02/Q04_Triple_DES/explanation.md): Lab 2 Triple DES encryption and decryption
  - Note: The manual repeats the same 8-byte DES component three times. That degenerates to single DES and PyCryptodome rejects it. The default is a corrected 24-byte key with distinct components; you can enter another valid key. CBC needs a fresh unpredictable IV for each encryption with the same key. Padding is not integrity protection.
- [Additional_Q03_AES_256](Lab_02/Additional_Q03_AES_256/explanation.md): Lab 2 AES-256 encryption and decryption
  - Note: 64 hex digits represent 32 bytes, selecting AES-256. CBC needs a fresh unpredictable IV for each encryption with the same key. Padding is not integrity protection.
- [Q03_DES_AES_Benchmark](Lab_02/Q03_DES_AES_Benchmark/explanation.md): Lab 2 Q3: DES versus AES-256 timing
- [Q05_AES_192_Round_Trace](Lab_02/Q05_AES_192_Round_Trace/explanation.md): Lab 2 Q5: AES-192 with every round shown
  - Note: The manual supplies only 32 hex digits for its AES-192 example, which is not a 24-byte key. This default corrects the length to 48 hex digits. The hand-written trace is educational; use the tested library for ordinary encryption.
- [Additional_Q01_Modes_Benchmark_Plot](Lab_02/Additional_Q01_Modes_Benchmark_Plot/explanation.md): Lab 2 additional Q1: Compare modes and plot timings
- [Additional_Q02_DES_Hex_Blocks](Lab_02/Additional_Q02_DES_Hex_Blocks/explanation.md): Lab 2 additional Q2: DES hexadecimal data
  - Note: The manual calls these Block1/Block2, but each is longer than one DES block (8 bytes). This program handles the complete byte sequences.
- [Additional_Q04_DES_CBC](Lab_02/Additional_Q04_DES_CBC/explanation.md): Lab 2 DES-CBC with an IV
  - Note: The fixed IV reproduces the exercise; generate a fresh IV for a new message in a real application.
- [Additional_Q05_AES_CTR](Lab_02/Additional_Q05_AES_CTR/explanation.md): Lab 2 AES-CTR with a nonce
  - Note: Interpret the 16 zero hex digits as an 8-byte nonce, leaving room for the counter in a 16-byte AES block. A 16-byte ASCII nonce would be too long. Never reuse a CTR nonce with the same key.

## Lab 3: Asymmetric key ciphers

- [Q01_RSA](Lab_03/Q01_RSA/explanation.md): Lab 3 Q1: RSA encryption
- [Q02_ECC](Lab_03/Q02_ECC/explanation.md): Lab 3: ECC encryption of Secure Transactions
  - Note: secp256r1 and NIST P-256 name the same curve. This explicitly implements hybrid ECC encryption, since a curve alone does not define a message-encryption scheme.
- [Additional_Q02_ECC](Lab_03/Additional_Q02_ECC/explanation.md): Lab 3: ECC encryption of Secure Transactions
  - Note: secp256r1 and NIST P-256 name the same curve. This explicitly implements hybrid ECC encryption, since a curve alone does not define a message-encryption scheme.
- [Q03_ElGamal](Lab_03/Q03_ElGamal/explanation.md): Lab 3 Q3: ElGamal encryption
  - Note: 256-bit finite-field ElGamal is only a quick demonstration size. The curve-based exercises below use P-256 instead. This byte-wise textbook scheme does not authenticate messages.
- [Q04_RSA_ECC_File_Transfer](Lab_03/Q04_RSA_ECC_File_Transfer/explanation.md): Lab 3 Q4: RSA versus ECC secure file transfer
  - Note: RSA cannot directly encrypt a 1 MB file. Hybrid encryption is necessary here. Timing includes some file/JSON work as shown in the function. The standalone solution simulates transfer through stored envelopes; the additional server.py/client.py perform actual TCP file transfer. The simulated benchmark shares recipient key material inside one process.
- [Q05_Diffie_Hellman](Lab_03/Q05_Diffie_Hellman/explanation.md): Lab 3 Q5: Diffie-Hellman peer key exchange
  - Note: Diffie-Hellman exchanges a key; it is not a signature or direct message-encryption algorithm. This isolated demonstration has no identity authentication. A complete communication system authenticates public values, as Lab 4 Q1 demonstrates.
- [Additional_Q01_Given_ElGamal](Lab_03/Additional_Q01_Given_ElGamal/explanation.md): Lab 3 additional Q1: ElGamal with supplied parameters
  - Note: These tiny fixed parameters are for arithmetic practice only. The consistency check explains any supplied-key mismatch before proceeding.
- [Additional_Q03_Textbook_RSA](Lab_03/Additional_Q03_Textbook_RSA/explanation.md): Lab 3 additional Q3: Textbook RSA with small parameters
  - Note: n=323=17*19 and phi(n)=288; 5*173 is 1 modulo 288. Raw byte-wise RSA provides no practical message security. Ordinary RSA examples use OAEP instead.
- [Additional_Q04_EC_ElGamal_Healthcare](Lab_03/Additional_Q04_EC_ElGamal_Healthcare/explanation.md): Lab 3 additional Q4: Healthcare encryption with EC-ElGamal
  - Note: This is a hybrid EC-ElGamal construction for learning, using P-256 (secp256r1). It is different from the finite-field ElGamal introduced earlier; both use the same masking idea with different mathematical groups.
- [Additional_Q05_Asymmetric_Comparison](Lab_03/Additional_Q05_Asymmetric_Comparison/explanation.md): Lab 3 additional Q5: RSA, curve ElGamal and ECC comparison
  - Note: The manual loosely mixes curve and finite-field ElGamal terminology. This solution respects its explicit secp256r1 requirement by using the curve version. Timings are measurements, not a universal ranking of algorithms.

## Lab 4: Advanced asymmetric cryptography

- [Q01_Enterprise_RSA_DH](Lab_04/Q01_Enterprise_RSA_DH/explanation.md): Lab 4 Q1: Enterprise RSA and Diffie-Hellman communication
  - Note: This is an in-process simulation of the endpoints, not a deployed network service. Public-key distribution uses the trusted local registry. Registry private keys are stored in an owner-only file; users with access to the OS account can still read them. Application revocation blocks future operations but cannot erase copies of old keys or plaintext already obtained.
- [Q02_Rabin_Hospital_KMS](Lab_04/Q02_Rabin_Hospital_KMS/explanation.md): Lab 4 Q2: Rabin hospital key-management service
  - Note: The API is a local Python function; there is no web server or claim of HIPAA compliance. Annual renewal occurs when the program runs, not while it is closed. Regenerating keys does not migrate old ciphertext: keep archived decryption keys in a production migration design. The local OS user is the service administrator. File permissions and an encrypted private-key field are teaching controls, not a full enterprise secret store. The Rabin wrapping format is illustrative, not standardized secure padding.
- [Additional_Q01_ElGamal_DRM](Lab_04/Additional_Q01_ElGamal_DRM/explanation.md): Lab 4 additional Q1: ElGamal digital rights management
  - Note: The manual proposes distributing a single master private key to customers. That would let every recipient decrypt all content and defeat granular revocation. This solution keeps the master private key inside the local service and distributes authorized decryption access instead. Creator/customer names select simulated identities, not authenticated logins. The OS user is trusted; the JSON file has owner-only permissions. Finite-field 256-bit keys are quick practice defaults; choose the requested 2048-bit size for the specified configuration. Renewal runs at startup, not while the program is closed.
- [Additional_Q02_Weak_RSA_Attack](Lab_04/Additional_Q02_Weak_RSA_Attack/explanation.md): Lab 4 additional Q2: Attack weak RSA primes
  - Note: No exact partial-private-key leakage model is supplied, so this does not claim to implement a specialized partial-key exposure attack. It demonstrates the stated weak-factor vulnerability. Trial division is bounded to avoid hanging on large public keys.

## Lab 5: Hashing

- [Q01_Custom_Hash](Lab_05/Q01_Custom_Hash/explanation.md): Lab 5 Q1: Custom 32-bit string hash
  - Note: For ASCII input ord(character) is the ASCII value. Python also accepts Unicode code points. This simple non-cryptographic hash has only 2^32 outputs and does not provide collision resistance suitable for signatures.
- [Q02_Hash_Client_Server](Lab_05/Q02_Hash_Client_Server/explanation.md): Lab 5 Q2: Network hash integrity
  - Note: A bare hash can demonstrate accidental corruption and this simulated tampering, but an active attacker who can change both data and digest can defeat this protocol. Use an authenticated channel, HMAC or a verified signature to establish authenticity. No encryption is claimed by this exercise.
- [Additional_Q01_Chunked_Hash](Lab_05/Additional_Q01_Chunked_Hash/explanation.md): Lab 5 additional Q1: Chunked network hash
  - Note: A bare hash can demonstrate accidental corruption and this simulated tampering, but an active attacker who can change both data and digest can defeat this protocol. Use an authenticated channel, HMAC or a verified signature to establish authenticity. No encryption is claimed by this exercise.
- [Q03_Hash_Performance_Collisions](Lab_05/Q03_Hash_Performance_Collisions/explanation.md): Lab 5 Q3: MD5, SHA-1 and SHA-256 experiment
  - Note: MD5 and SHA-1 have known cryptographic collision weaknesses; random sampling of 50–100 strings does not reproduce those attacks. SHA-256 is the appropriate secure-hash example among these three. The experiment measures local execution time and observed sample collisions only.

## Lab 6: Digital signatures

- [Q00_RSA_Signature_Walkthrough](Lab_06/Q00_RSA_Signature_Walkthrough/explanation.md): Lab 6 walkthrough: RSA digital signatures
  - Note: The manual website walkthrough asks participants to exchange private keys. That is incorrect for a secure signature workflow: exchange only public keys. This program uses fresh separate identities and PKCS#1 v1.5 signatures rather than reproducing insecure website key handling.
- [Q01_ElGamal_Schnorr_Signatures](Lab_06/Q01_ElGamal_Schnorr_Signatures/explanation.md): Lab 6 Q1: ElGamal and Schnorr signatures
  - Note: The small finite-field size is for quick arithmetic practice. Never reuse signature nonces: doing so can expose private keys. These readable textbook implementations are not standardized production signature encodings.
- [Q02_DH_And_Authentication](Lab_06/Q02_DH_And_Authentication/explanation.md): Lab 6 Q2: Diffie-Hellman with message authentication
  - Note: This explicitly corrects the manual’s conflation of Diffie-Hellman with signature algorithms. Bare DH still needs authenticated public-key exchange to prevent an active intermediary.
- [Q03_Signature_Client_Server](Lab_06/Q03_Signature_Client_Server/explanation.md): Lab 6 Q3: Client/server signature and DH authentication
  - Note: Client setup must happen before the server starts. Private keys are never sent. ElGamal/Schnorr use quick 256-bit finite-field practice parameters. DH-HMAC is a shared-secret authentication demonstration, not a digital signature or a fully mutually authenticated network protocol. The server trusts the client public identity through prior local setup.
- [Additional_Q01_RSA_SHA_CIA](Lab_06/Additional_Q01_RSA_SHA_CIA/explanation.md): Lab 6 additional Q1: RSA encryption, hashing and signatures
  - Note: The manual calls this the CIA triad. Encryption and signatures do not establish availability, so this solution explicitly distinguishes the demonstrated properties. It uses local functions rather than relying on a website or exposing private keys online.

## Lab 7: Partial homomorphic encryption

- [Q01_Paillier_Addition](Lab_07/Q01_Paillier_Addition/explanation.md): Lab 7 Q1: Paillier homomorphic addition
  - Note: The manual sample labeled Paillier uses RSA-derived values and incorrect formulas. This implementation uses actual Paillier arithmetic modulo n^2. Ciphertext multiplication means plaintext addition. The 512-bit default is for quick practice, not a production key size.
- [Q02_RSA_Multiplication](Lab_07/Q02_RSA_Multiplication/explanation.md): Lab 7 Q2: RSA homomorphic multiplication
  - Note: This is textbook RSA with small parameters because the exercise is about homomorphic arithmetic. It is intentionally separate from secure RSA-OAEP encryption. Products wrap modulo n; they are not unrestricted integers.
- [Additional_Q01a_ElGamal_Multiplication](Lab_07/Additional_Q01a_ElGamal_Multiplication/explanation.md): Lab 7 additional 1a: ElGamal homomorphic multiplication
  - Note: The medical example in the manual incorrectly claims ordinary ElGamal provides homomorphic greater-than comparison. Ciphertext multiplication does not implement comparison. This exercise demonstrates the actual multiplicative property.
- [Additional_Q01b_Secure_Data_Sharing](Lab_07/Additional_Q01b_Secure_Data_Sharing/explanation.md): Lab 7 additional 1b: Secure data sharing using Paillier
  - Note: All roles are simulated in one Python process. In a deployed system the aggregator should not receive the private key. The program decrypts only the final aggregate and does not claim to authenticate owner contributions.
- [Additional_Q01c_Threshold_Control](Lab_07/Additional_Q01c_Threshold_Control/explanation.md): Lab 7 additional 1c: Custodian threshold for final decryption
  - Note: This is Shamir threshold CONTROL over Paillier decryption, not a cryptographically distributed threshold-Paillier protocol: the private exponent is reconstructed in one process. That distinction is explicit. Production threshold decryption instead combines partial decryptions without recreating the full private key. Shares, roles and custodian delivery are simulated here; shares are not printed.
- [Additional_Q01d_PHE_Benchmark](Lab_07/Additional_Q01d_PHE_Benchmark/explanation.md): Lab 7 additional 1d: Paillier and ElGamal benchmarking
  - Note: Safe-prime ElGamal key generation can take longer and varies by run. This benchmark uses small teaching parameters and checks the decrypted result each time. Equal modulus sizes do not imply equal security or equivalent supported operations.

## Lab 8: Searchable encryption

- [Q01_Symmetric_Searchable_Encryption](Lab_08/Q01_Symmetric_Searchable_Encryption/explanation.md): Lab 8 Q1: Symmetric searchable encryption
  - Note: The manual tries to match freshly randomized AES encryptions; they will not compare equal. This solution uses HMAC for stable lookup and AES-GCM for encrypted contents/posting lists. It is an educational SSE design and leaks repeated-search patterns and result/access patterns. The local key file is owner-only, but the OS user is trusted.
- [Q02_Paillier_Public_Key_Search](Lab_08/Q02_Paillier_Public_Key_Search/explanation.md): Lab 8 Q2: Paillier-encrypted documents and searchable index
  - Note: This is a hybrid public-key-encrypted corpus with a symmetric keyed search token, not a complete formal public-key encryption-with-keyword-search (PEKS) scheme. Paillier alone does not supply a public equality-test trapdoor. The manual’s randomized-ciphertext dictionary lookup cannot work as written. Writers need the public encryption key plus the token key to index new words; private keys are needed only to recover results. The program states this additional assumption explicitly.
- [Additional_Q01_GnuPG](Lab_08/Additional_Q01_GnuPG/explanation.md): Lab 8 additional Q1: GnuPG encryption and signatures
  - Note: Requires the separate gpg executable, not just a pip library. Uses an isolated keyring, never your personal keyring. Unprotected lab private keys are only for this exercise; protect real private keys with a passphrase. Copying files simulates transmission; this program does not send messages or upload data. The trusted local fingerprint is explicit; real recipients must authenticate public keys.
- [Additional_Q02_Snort_NIDS](Lab_08/Additional_Q02_Snort_NIDS/explanation.md): Lab 8 additional Q2: Snort intrusion detection
  - Note: Requires the separate Snort executable and a compatible local installation/configuration. Offline analysis needs no live capture privileges. Live monitoring may require OS capture permissions and reports setup errors; it never runs sudo automatically. The sample rule is a known demonstration marker, not evidence that an arbitrary real packet is malicious. Snort itself is unavailable in this workspace, so actual Snort alert generation must be checked where it is installed.

