# Q3: Secure grant expense portal

## 1. The original question

SECURE GRANT EXPENSE PORTAL

Scenario:

A research institute manages grant expenses through an online portal. Researchers submit grant details, reviewers check their integrity and authenticity, and the finance officer computes the total grant expenditure. The system must keep grant data confidential and verifiable, and the total must be computed without decrypting individual amounts.

Requirements:

Researcher side: The researcher enters a Grant ID, Grant Description and Grant Amount. Before storing, the system:

Encrypts the grant description with AES-192.
Encrypts the grant amount with the Paillier cryptosystem.
Computes an MD5 hash of the grant record.
Signs the hash with an RSA digital signature.
The researcher can submit grant details, and view all submitted records, including those entered earlier.

Reviewer side: The reviewer verifies the RSA signature and recomputes the MD5 hash to detect tampering. The reviewer can search the stored records by index (Grant ID) without exposing the encrypted contents. The reviewer can also view the AES-192 decrypted grant description as a hexadecimal dump.

Finance Officer side: The finance officer homomorphically aggregates the Paillier-encrypted amounts of the selected grants. The officer then verifies the signatures and decrypts only the final aggregate, never individual amounts.

Task:

Write a menu-driven Python program implementing the above roles and functions. Use role-based menus and cryptographic operations for confidentiality, integrity and authenticity. Store the encrypted, hashed and signed records persistently (file or database), so that earlier entries remain visible after a restart. Handle invalid input and tampered records gracefully. Display outputs for all functions.

Note: If the Python code is not menu-driven, the total marks obtained will be reduced to half.

## 2. What you are building, in plain English

Researcher submits encrypted grants. Reviewer checks encrypted-record integrity and reads descriptions. Finance adds encrypted amounts and decrypts only the final sum. Password-checked roles constrain each menu and sensitive function.

This solution is intentionally split into small functions. Read the menu first to understand what the user can do, then follow the function calls. Every function has an input/operation/output/usage comment in the Python source and is explained again below.

## 3. Basic vocabulary before reading the code

| Term | Meaning in these programs | What you should say in a viva |
|---|---|---|
| Plaintext | Original message or record bytes | Encryption starts from plaintext. |
| Ciphertext | Encrypted bytes or encrypted integer | You need the correct key to recover the original value. |
| AES key | Secret 16/24/32 bytes | AES-192 means 24 bytes, AES-256 means 32; block size remains 16 bytes. |
| IV / nonce | Per-encryption parameter stored with ciphertext | It is not the secret key; use a fresh value with each encryption. |
| SHA/MD5 digest | Fixed-size fingerprint of exact bytes | Hashing is one-way, so it cannot be decrypted. |
| Signature | Private-key proof over a hash | Sign with private key; verify with the trusted public key. |
| HMAC token | Deterministic keyed lookup value | The same normalized keyword gives the same token for indexing. |
| Paillier aggregate | Product of ciphertexts modulo n squared | It decrypts to a sum of plaintext numbers modulo n. |
| Canonical JSON | Sorted keys and stable separators encoded as UTF-8 | Sender and verifier hash exactly the same representation. |
| Expiry | Persisted issue time plus lifetime | Restarting must not give an old key another lifetime. |


## 4. Install and run

The only third-party Python package is PyCryptodome. From the **project root**, where Labs and PYQ_Solutions live:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r PYQ_Solutions/requirements.txt
.venv/bin/python PYQ_Solutions/Q03_Grant_Expense_Portal/solution.py
```

Your existing `.venv` already has this package in the current workspace. On Windows use `.venv\Scripts\python.exe` instead. If your terminal is inside this question folder, run `../../.venv/bin/python solution.py`. Enter normal menu choices; there is no special command-line run mode. When a default appears in square brackets, Enter accepts it. Q1 deliberately requires its exam parameters without numeric defaults.

First-run account passwords are hidden while typing in a normal terminal. Remember the passwords you set: the programs do not install default shared passwords. The KDF password used for a report or voter credential is distinct from a role login password.

## 5. A complete worked run

On first launch create three passwords: researcher, reviewer, finance. Login as researcher and submit G001 / Microscope / 1250.50, then G002 / Lab supplies / 249.50. View encrypted submissions; logout. Login as reviewer, find G001 and verify it, then display its description as hex (4d 69 63 72 6f 73 63 6f 70 65). Logout; login as finance and aggregate G001,G002: total 1500.00. Exit and reopen: both grants remain visible. To test tampering without altering original study files, copy the question folder, change one amount ciphertext digit in the copied storage/grants.json, and rerun reviewer verification/finance aggregate: both must reject.

## 6. The algorithm, step by step

1. Create/load role accounts and cryptographic keys. AES description key is exactly 24 bytes.
2. Convert amount text into exact integer paise. Reject negative values, excessive precision and duplicate IDs.
3. AES-192-GCM encrypt description and Paillier-encrypt amount.
4. Create canonical encrypted grant record, compute MD5, sign that MD5 digest using RSA PKCS#1 v1.5.
5. Persist encrypted record, HMAC Grant-ID index, digest and signature.
6. Reviewer recomputes MD5 and verifies RSA on stored encrypted bytes without decrypting the amount.
7. Reviewer alone may decrypt the selected description and display its hex dump.
8. Finance forms ciphertext aggregate; signatures must all verify before aggregate decryption.

Cryptographic ciphertexts, IVs, salts, nonces and signatures can vary between runs because encryption and key generation use randomness. Compare the recovered plaintext, verification booleans, search results and totals instead of expecting a fixed long ciphertext string. Q1 uses raw deterministic RSA, so its fixed worked example does reproduce the same small ciphertext integers.

## 7. What is saved and why

storage/grants.json stores encrypted records and the Grant-ID index. keys.json stores AES-192, RSA, Paillier and HMAC keys. accounts.json stores salted password hashes (not plaintext passwords). audit.jsonl chains/signs operation events. All paths are relative to this script location.

All generated state is written beside the script under the documented subfolders. Changing your terminal's current directory does not redirect the records. Reopening loads the previous keys and data. Keep the key files with the encrypted data; deleting keys does not decrypt or reset existing records. To start a completely separate practice run, copy the question folder to a new location before generating data.

## 8. Every Python function explained

Read functions in their file order. Inputs named `public` hold shareable encryption/verification parameters; `private`, `keys`, `record_keys` or `credentials` may contain secrets and must not be sent with an untrusted request.

### File: `solution.py`

#### `ask_text(label, default=None)`

Input: prompt and optional default. Read terminal text; Enter accepts a supplied default.

Output: nonempty string. Use ask_text('Patient ID') when a value must be entered.

Follow these calls when reading the implementation: `ValueError`, `input`.

#### `canonical(record)`

Input: JSON-compatible record. Sort keys and remove irrelevant spaces consistently.

Output: UTF-8 bytes. Hash/sign these exact bytes so dictionary formatting cannot change results.

#### `read_json(path, default=None)`

Input: JSON file path and optional missing-file default. Parse saved records.

Output: decoded JSON. Invalid JSON raises an error instead of silently replacing damaged data.

Follow these calls when reading the implementation: `Path`.

#### `save_json(path, record, secret=False)`

Input: path, record and secret-file flag. Write via a temporary file then replace atomically.

Output: saved JSON file; returns nothing. Secret files receive owner-only permissions.

Follow these calls when reading the implementation: `Path`.

#### `parse_amount(text)`

Input: money text with up to two decimal places. Convert exactly into integer paise.

Output: nonnegative integer. Reject fractional paise, nonfinite values and negatives.

Follow these calls when reading the implementation: `Decimal`, `ValueError`.

#### `format_amount(paise)`

Input: integer paise. Convert to a two-decimal display without floating-point rounding.

Output: string such as 125.50. Use after decrypting a final monetary total.

#### `seal(data, key)`

Input: plaintext bytes and 16/24/32-byte AES key. Encrypt/authenticate using GCM.

Output: JSON-safe nonce/ciphertext/tag dictionary. Save all three for verified decryption.

#### `open_seal(envelope, key)`

Input: saved AES-GCM envelope and matching key. Verify the tag before returning data.

Output: plaintext bytes; wrong keys/modified ciphertext raise ValueError.

#### `rsa_sign(private_pem, data, algorithm='sha256')`

Input: RSA private PEM, bytes to sign and sha256/md5/sha512 selection. Hash once and sign.

Output: PKCS#1 v1.5 signature as hex. Private keys remain local; public keys verify.

#### `rsa_verify(public_pem, data, signature, algorithm='sha256')`

Input: trusted RSA public PEM, original bytes, signature hex and hash selection.

Output: True if the signature matches; False for altered data, key or signature encoding.

#### `rsa_pair(bits=2048)`

Input: RSA modulus bits. Ask PyCryptodome to generate a fresh key pair.

Output: dictionary of private/public PEM strings. Save the private part in a secret file.

#### `paillier_keys(bits=512)`

Input: demonstration modulus size. Generate distinct primes and g=n+1 Paillier keys.

Output: public n/g and private lambda/mu dictionaries. Public key encrypts/sums; private decrypts.

Follow these calls when reading the implementation: `ValueError`, `getPrime`, `pow`.

#### `random_unit(n)`

Input: modulus. Choose a random value in 1..n-1 that has a modular inverse.

Output: coprime random integer. Used as Paillier randomness and proof randomness.

#### `paillier_encrypt(public, value, return_randomness=False)`

Input: public key and integer in 0..n-1; optionally request the random witness.

Output: ciphertext, or (ciphertext,r) for ballot proofs. Never publish an individual vote's r.

Follow these calls when reading the implementation: `random_unit`, `ValueError`, `pow`.

#### `check_ciphertext(public, ciphertext)`

Input: Paillier public key and untrusted ciphertext integer. Validate its group/range.

Output: nothing; raise ValueError if it is not an invertible element modulo n squared.

Follow these calls when reading the implementation: `ValueError`.

#### `encrypted_sum(public, ciphertexts)`

Input: public Paillier key and ciphertext list. Multiply valid ciphertexts modulo n squared.

Output: encrypted sum modulo n. This function has no private-key parameter and cannot decrypt inputs.

Follow these calls when reading the implementation: `check_ciphertext`.

#### `paillier_decrypt(public, private, ciphertext)`

Input: matching keys and aggregate ciphertext. Apply Paillier's L function and private inverse.

Output: plaintext integer modulo n. Application roles decide which aggregates may be decrypted.

Follow these calls when reading the implementation: `check_ciphertext`, `pow`.

#### `token(key, text)`

Input: secret HMAC key and already normalized lookup string. Compute deterministic keyed hash.

Output: hex lookup token. A search computes the same token without bulk decryption.

#### `setup_accounts(path, roles)`

Input: account file path and role names. On first use ask for each role's new password twice.

Output: saved salted PBKDF2 password records. Existing passwords are never silently replaced.

Follow these calls when reading the implementation: `read_json`, `save_json`, `get_random_bytes`, `PBKDF2`, `ValueError`.

#### `authenticate(accounts, username, password)`

Input: saved accounts, username and entered password. Derive and compare the salted password hash.

Output: role string on success; ValueError on unknown account or wrong password.

Follow these calls when reading the implementation: `PBKDF2`, `ValueError`.

#### `login(accounts)`

Input: username and hidden password from the terminal. Authenticate a previously created account.

Output: username and assigned role; callers use that role to choose the allowed menu.

Follow these calls when reading the implementation: `ask_text`, `authenticate`.

#### `require_role(actual, allowed)`

Input: authenticated role and allowed-role collection. Check permission inside the operation itself.

Output: nothing on success; PermissionError on denial. Menus alone are not authorization checks.

Follow these calls when reading the implementation: `PermissionError`.

#### `audit(folder, event, details, private_pem)`

Input: audit directory, event name, details and signing key. Chain and sign a new audit entry.

Output: appended JSONL event. The previous-entry digest exposes edits, reordering and gaps.

Follow these calls when reading the implementation: `rsa_sign`, `Path`, `canonical`.

#### `verify_audit(folder, public_pem)`

Input: audit directory and trusted signing public key. Verify signatures and previous-entry chain.

Output: True when existing entries are intact. External anchoring is needed to detect deletion of the final suffix.

Follow these calls when reading the implementation: `Path`, `rsa_verify`, `canonical`.

#### `initialize_portal(folder)`

Input: portal storage directory. Generate persistent AES-192, RSA, HMAC and Paillier keys once.

Output: key dictionary and grant registry. Existing records and keys survive program restarts.

Follow these calls when reading the implementation: `read_json`, `paillier_keys`, `save_json`, `rsa_pair`, `get_random_bytes`.

#### `grant_payload(record)`

Input: stored grant including digest/signature. Select the encrypted fields that must be authenticated.

Output: record dictionary excluding digest and signature, preventing recursive signing.

#### `verify_grant(record, keys)`

Input: stored encrypted grant and trusted RSA public key. Recompute MD5 and verify its RSA signature.

Output: True only when both checks pass; no description or amount decryption is needed.

Follow these calls when reading the implementation: `canonical`, `grant_payload`, `rsa_verify`.

#### `submit_grant(registry, keys, role, grant_id, description, amount_paise, researcher)`

Input: registry, keys, authenticated researcher role, grant fields and integer paise.

Output: signed encrypted grant inserted in place. Reject duplicate IDs and out-of-range amounts.

Follow these calls when reading the implementation: `require_role`, `token`, `canonical`, `rsa_sign`, `ValueError`, `seal`, `paillier_encrypt`.

#### `find_grant(registry, keys, role, grant_id)`

Input: registry, lookup key, allowed role and exact grant ID. Select one indexed record.

Output: stored grant after identity/signature checks; ciphertext contents remain encrypted.

Follow these calls when reading the implementation: `require_role`, `token`, `ValueError`, `verify_grant`.

#### `review_description(registry, keys, role, grant_id)`

Input: authenticated reviewer role and grant ID. Verify then AES-decrypt only its description.

Output: plaintext description bytes; display as a hexadecimal dump in the reviewer menu.

Follow these calls when reading the implementation: `require_role`, `find_grant`, `open_seal`.

#### `aggregate_grants(registry, keys, role, grant_ids)`

Input: finance role and distinct selected grant IDs. Aggregate only encrypted amounts, verify and decrypt total.

Output: encrypted total and final integer paise. Reject all selected data if any signature is invalid.

Follow these calls when reading the implementation: `require_role`, `encrypted_sum`, `ValueError`, `token`, `paillier_decrypt`, `verify_grant`.

#### `role_menu(folder, keys, registry, username, role)`

Input: authenticated role/session and persisted portal state. Expose only allowed operations.

Output: saved submissions, verification/search results or aggregate totals; return on logout.

Follow these calls when reading the implementation: `ask_text`, `submit_grant`, `save_json`, `audit`, `parse_amount`, `find_grant`, `verify_grant`, `review_description`, `aggregate_grants`, `format_amount`.

#### `main()`

Input: first-run role passwords, then login/menu choices. Start the persistent grant portal.

Output: role-based menu, encrypted JSON records and signed audit trail. Run python solution.py.

Follow these calls when reading the implementation: `initialize_portal`, `setup_accounts`, `ask_text`, `login`, `role_menu`, `audit`, `Path`, `verify_audit`.

## 9. How to read the menu code

`solution.py` begins here when you run it:

```python
def main():
    """Input: first-run role passwords, then login/menu choices. Start the persistent grant portal.
    Output: role-based menu, encrypted JSON records and signed audit trail. Run python solution.py.
    """
    folder = Path(__file__).resolve().parent / "storage"
    keys, registry = initialize_portal(folder)
    accounts = setup_accounts(folder / "accounts.json", ("researcher", "reviewer", "finance"))
    while True:
        print("\n1 Login  2 Verify audit trail  0 Exit")
        try:
            choice = ask_text("Choice")
            if choice == "0":
                return
            if choice == "1":
                username, role = login(accounts)
                role_menu(folder, keys, registry, username, role)
            elif choice == "2":
                print("Audit verified:", verify_audit(folder, keys["rsa"]["public"]))
            else:
                print("Choose a listed option.")
        except (ValueError, PermissionError, OSError) as error:
            print("Rejected:", error)
            audit(folder, "login_rejected", {"reason": str(error)}, keys["rsa"]["private"])
```

The `if __name__ == "__main__": main()` line at the bottom starts the menu when the file is run directly. Importing the file to reuse its functions does not automatically start the menu. A `try/except` around each operation turns ordinary bad input into a readable error so you can return to the menu.

## 10. Python details that matter here

- `text.encode()` converts Python text into bytes. Cryptographic libraries operate on bytes, not Python strings.
- `bytes.fromhex(text)` restores bytes from a printed hexadecimal string; `.hex()` does the reverse.
- A dictionary such as `record['signature']` keeps named fields together without defining a class.
- `pow(a, e, n)` computes modular exponentiation efficiently; `pow(a, -1, n)` computes a modular inverse when one exists.
- `canonical(record)` is used before hashing/signing. Never hash an ordinary dictionary representation or rely on key insertion order.
- A verifier must check the signature with a **previously trusted** public key. A key supplied by an unknown sender does not prove identity.
- Menu code gathers inputs. Separate functions do cryptography, indexing, authorization and storage so you can adapt the question without rewriting everything.
- Cryptographic API calls such as `AES.new(...)` return library cipher objects. You do not define classes or use object-oriented application design in these solutions.

## 11. Verification, failures and exam modifications

- First perform the successful worked run, then repeat with different input values.
- Try a missing record ID, an unlisted menu choice, the wrong role, an incorrect password, or a changed ciphertext/signature where applicable. The operation should fail rather than print an apparently valid result.
- Always verify before exposing selected plaintext. Do not continue decryption after a failed integrity check.
- Search must use an index; do not decrypt every record to test whether a keyword occurs.
- For homomorphic totals, aggregation receives the public key and ciphertexts. Keep private-key decryption at the final result step.
- Match the question's exact key length, hash and cipher mode. AES-192-CBC is not interchangeable with AES-256-GCM when the question specifically requests CBC.
- If the examiner changes field names or the application story, adapt the input/record dictionaries and menus. Keep the canonical serialization, key handling, verification order and mathematical functions.
- If you edit data legitimately, encrypt/sign the new state through the authorized function. Editing JSON directly is a tampering test, not an authorized update.

## 12. Assumptions, corrections and practical limits

The question does not define what exact bytes constitute the hashed grant record. Here MD5 covers the canonical ENCRYPTED record, including ID, encrypted description/amount and creation metadata, so reviewers can recompute it without exposing individual amounts. MD5 is included because this PYQ specifically requires it; SHA-256 is preferable for a new design. Roles are authenticated within this local lab application, but a person who controls the OS account and key files controls the simulation. Paillier defaults to a small teaching modulus. Signed audit chains expose internal changes but require external anchoring to detect removal of an entire final suffix.

