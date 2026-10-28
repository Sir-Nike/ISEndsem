# Skeleton 3: local role-based encrypted records

## Run this one program

From the project root:

```bash
.venv/bin/python -m pip install -r skeleton/Skeleton_3/requirements.txt
.venv/bin/python skeleton/Skeleton_3/skeleton.py
```

One program, one terminal, no sockets, no helper modules to copy, and no special run flags. On first run it asks for an admin password of at least eight characters. The admin username is admin. On later runs it reuses the accounts, keys, records and audit files under practice_data/ beside the script. Paths do not depend on your terminal's current directory.

## Worked example

1. Run the program, choose your first admin password, then choose 1 Login and log in as admin.
2. Select Manage users -> Create user. Create alice with role sender, bob with role receiver, and reviewer with role reviewer. Choose a separate password for each. Each Manage users action returns to the admin menu; select it again to create the next account.
3. Log out. Log in as bob once. The program creates his RSA private/public pair and registers only his public key. Log out. The receiver must exist and have registered its key before a sender can save a message addressed to it.
4. Log in as alice. Her ElGamal pair is created/registered automatically. Choose Enter and save message. Enter bob, unique ID R001, and Hello exam. Encryption, key wrapping, signing, hashing and persistence all happen automatically.
5. Log out and log in as reviewer. View records, then Verify record -> R001. Every check should be True. No plaintext is displayed.
6. Log out and log in as bob. Choose Verify and decrypt message -> R001. The program verifies everything before recovering the AES key and displaying Hello exam.
7. Log in as admin, choose Tamper with a practice record -> R001 -> ciphertext. The copied record's overall result should be False. For target audit, audit_valid should be False. The original stays valid.
8. Choose View logs and verify audit to inspect the signed events, including verification/decryption outcomes and tampering practice. Exit and restart: accounts and records remain, but old session tokens do not.

## Compact menus

```text
Main
  1 Login
  0 Exit

Sender
  1 Enter and save message
  2 View my submissions
  0 Logout

Reviewer
  1 View records
  2 Verify record
  0 Logout

Receiver
  1 View received messages
  2 Verify and decrypt message
  0 Logout

Admin
  1 Manage users
  2 View logs and verify audit
  3 Tamper with a practice record
  0 Logout
```

Manage users has create, disable and list choices. An admin does not automatically get permission to decrypt other people's records. Each high-level function checks role permissions internally; hiding menu choices alone is not the authorization mechanism.

## What changed from Skeleton 1?

The message cryptography is the same: AES-256-GCM, RSA-2048 OAEP/SHA-256 for wrapping AES keys, SHA-256 record digest and ElGamal/SHA-256 signatures. Skeleton 3 adds user login, per-user identities, role/ownership enforcement, multiple persistent records, signed record-index bindings, logs, signed audit, and a tamper-copy exercise.

There is no client/server step to study. Save_Message calls the encryption functions and Submit directly. Verify_Record reads local files. Decrypt_Record reads local files and calls key unwrap/decryption directly. Function arguments and .txt files carry all data between operations.

## Read the main workflow first

### Setup and login

Setup generates the application's audit/storage signing key and signs the initial users.txt, catalog.txt and audit.txt. The first admin password becomes a salted scrypt verifier, not plaintext. Load_State loads that same key on restart and checks the signed account and audit files.

Login verifies credentials and account status, then returns an unpredictable token. Require finds that token in memory, checks its 30-minute monotonic lifetime, loads the current role from the signed account file, and checks permission. The role is not taken from a user-provided string. Disabling a user invalidates active tokens. Five failed logins for a username impose a 60-second in-memory lockout. Logout removes its token.

Ensure_User_Keys runs automatically after sender/receiver login. It generates or validates the user's local pair and registers its public half. Existing identities are not replaced when a private file goes missing: the original private key must be restored. Reviewer/admin roles need no message signing/decryption pair.

### Sender: Save_Message

```text
Receiver username + unique ID + plaintext
    -> read sender ElGamal private key and registered public key
    -> load recipient's registered RSA public key
    -> Generate_Symmetric_Key: fresh random 32 bytes
    -> Encrypt: AES-256-GCM with fresh 12-byte nonce
    -> Encrypt_Key: wrap AES key with recipient RSA public key
    -> build package with metadata, ciphertext, nonce, tag, wrapped key and public keys
    -> Canonical: deterministic bytes
    -> Hash_Generate: SHA-256 of those bytes
    -> DS_Sign: ElGamal signature of those bytes, internally hashed with SHA-256
    -> Submit: check identity, keys, hash/signature and unique ID, then save artifacts/catalog/audit
    -> save latest sender AES key separately in its private identity directory
```

Metadata names record ID, sender, receiver, algorithm labels and both public-key fingerprints. Encrypt authenticates this metadata as GCM additional authenticated data (AAD). The signature covers the entire encrypted package, including wrapped key and metadata. The hash/signature files are outside that package to avoid a circular signature definition.

The separate SHA-256 digest is not a substitute for signing: an attacker could modify data and replace an unkeyed digest. DS_Verify must also pass against the public key registered in signed users.txt. Do not trust only the public key supplied with a record.

Each ID accepts letters, digits, underscore and hyphen, up to 64 characters. Duplicate IDs are rejected rather than overwriting older messages. The sender's latest private AES file is overwritten per new accepted message; each record retains its own RSA-wrapped AES key and remains decryptable.

### Reviewer: Verify_Record

Get_Entry first checks session role and permitted record visibility. Check_Stored reads the .txt artifacts, obtains the registered public keys from signed users.txt, and checks package metadata, fingerprints, ElGamal signature and SHA-256 hash. It also checks the signed catalog's complete packet digest and ID/sender/receiver bindings. False results are audited as detected tampering.

Reviewer sees results and metadata only. Sender can verify/list its own records; receiver can verify/list addressed records. Reviewers/admin can inspect all public summaries. None of these checks needs either user's private key or the saved plaintext AES key.

### Receiver: Decrypt_Record

Get_Entry requires receiver role and matching recipient. Check_Stored must return overall=True before private material is read. Decrypt_Key uses the receiver's existing RSA private key to recover AES from encrypted_key.txt. Decrypt uses the recovered key, stored nonce, identical AAD metadata and GCM tag; decrypt_and_verify releases bytes only after authentication. Then the program decodes UTF-8 and displays plaintext.

It does not read the sender's private signing key or the sender's saved AES key. It does not save plaintext or the recovered AES key. In this local program a successful decryption can be audited as DECRYPT_OK because the operation happens inside the program. A wrong private key/GCM tag/file generates a rejection event.

## Why JSON is still used

JSON packages dictionaries, integer signatures and metadata as text. It is used for local storage and consistent signing bytes, not networking. The files still have .txt extensions. Ciphertext/key/tag/nonce bytes become hexadecimal strings; PEM keys are already text.

Canonical sorts dictionary keys, fixes separators and UTF-8 encodes the JSON. Signing and verifying must use the exact same representation. Package whitespace in saved JSON is not signed as raw file formatting: reconstructed field values are signed. Changing a signed value is detected.

## Storage: each artifact is separate .txt

```text
practice_data/
  signing_private_key.txt          application-only RSA audit/storage private key
  signing_public_key.txt
  users.txt                        signed roles, scrypt verifiers and public registrations
  catalog.txt                      signed record index, recipients and complete packet digests
  audit.txt                        signed hash-chained event snapshot
  activity_log.txt                 operational diagnostics
  identities/<username>/
    private_key.txt                sender ElGamal OR receiver RSA private key
    public_key.txt
    symmetric_key.txt              sender's latest plaintext AES key only
  records/<ID>/
    ciphertext.txt
    nonce.txt
    tag.txt
    encrypted_key.txt
    metadata.txt
    sender_public.txt
    receiver_public.txt
    signature.txt
    hash.txt
  tamper_practice/<ID>/             copied/modified artifacts or audit_copy.txt
```

Private files have owner-only permissions and are unencrypted local teaching files. Hex/JSON/PEM and .txt extensions do not encrypt a private key. Keep practice_data private. The application uses registered public keys from the signed account database, not a public identity freely chosen by a record file.

File writes for signed snapshots use temporary .txt files and atomic replacement. The nine record artifacts, catalog and audit are not one database transaction. A crash can leave an orphan or partially saved record folder. Run one instance per practice_data directory; concurrent writers are not supported.

## Logging, audit and metadata tampering

activity_log.txt records local operation names, actor, record ID and error categories. It does not record passwords, tokens, plaintext or private/AES key values. It is a diagnostic log, not signed evidence. The signed audit is the security-relevant record.

Audit adds sequence number, previous-event hash, UTC application-clock time, actor, action and non-secret details. Root_Sign signs the complete audit snapshot with a separate application RSA-PSS/SHA-256 key. Audit_Read checks that signature and every sequence/hash link. Changed events, reordered events or a deleted tail without a new valid signature fail verification. Account data and catalog are also signed with this separate key; message signatures still use the sender's ElGamal key.

Metadata and key-fingerprint changes fail the message signature and catalog binding; metadata is also GCM AAD. Changing source files directly does not make an unauthorized recipient change valid. Current menus do not implement legitimate record updates; add a new version/update workflow if the exam requires it.

Admin Tamper_Test copies the selected record and alters one target without repairing signatures. It supports ciphertext, nonce, tag, encrypted_key, metadata, public_key, signature, hash, and audit. Audit target removes an event from a copied snapshot. The function reports the rejection and appends TAMPER_PRACTICE to the untouched live audit. The original record stays valid.

A live-file modification in a temporary test copy is detected at the next verification/list/decryption. A real damaged file is refused; the app does not automatically re-sign corruption as legitimate. Restore trusted original data rather than changing the stored hash/signature to hide the failure.

## Replacing algorithms in the exam

All code is in skeleton.py. Keep these interfaces when replacing functions with matching lab code:

| Function | Inputs | Output |
| --- | --- | --- |
| Encrypt | plaintext bytes, symmetric key bytes, AAD bytes | ciphertext/nonce/tag dictionary with hex values |
| Decrypt | envelope dictionary, recovered symmetric key, identical AAD | plaintext bytes |
| Encrypt_Key | AES bytes, receiver public PEM | wrapped key hex text |
| Decrypt_Key | wrapped key text, receiver private PEM | AES bytes |
| DS_Sign | canonical message bytes, sender private dict | JSON-compatible signature dictionary |
| DS_Verify | message bytes, signature, registered public key | bool |
| Hash_Generate | canonical message bytes | hex digest string |
| Hash_Check | message bytes, expected digest | bool |

A key type change also needs Generate_Sender_Keys/Generate_Receiver_Keys, Ensure_User_Keys, Public_Fingerprint and Register_Key adapted. Update Metadata labels and storage helpers if the envelope format changes. Switching GCM to CBC adds IV/padding handling. Hashing a plaintext file rather than ciphertext requires a deliberate change to which bytes are hashed and when verification can occur.

ElGamal defaults to a 256-bit safe-prime practice group for fast lab execution, not a production security size. Generate_Sender_Keys uses Crypto.PublicKey.ElGamal.generate; the signature functions retain the readable textbook equations because the public library signing method is unimplemented. Set exam-required parameters before first identity generation; existing registrations are reused.

## Limits of a local role program

Role checks enforce allowed operations inside this program. Anyone controlling the same OS account or Python process can inspect/edit local private files or call internal crypto helpers. These menus do not isolate mutually untrusted OS users. The separate application signing key and account registry are trusted.

Audit timestamps use the local clock, not an external trusted timestamp authority. Restoring an older valid copy of the entire signed state/audit can evade local rollback detection; an external trusted checkpoint would be needed. There is no Paillier, searchable index, KDF-based record-key expiry, threshold decryption, key rotation, password recovery or networking. Password verification does use scrypt, which is distinct from a record encryption KDF/expiry workflow.

## Library usage

Use the relevant PyCryptodome API for each operation: Crypto.Cipher.AES for AES-GCM, Crypto.PublicKey.RSA for RSA key pairs, Crypto.Cipher.PKCS1_OAEP for AES-key wrapping, Crypto.Hash.SHA256 for hashing, and Crypto.PublicKey.ElGamal.generate for sender key generation. Skeletons 2 and 3 also use Crypto.Protocol.KDF.scrypt for password verifiers and Crypto.Signature.pss for the separate application audit/storage signatures.

ElGamal.generate returns library integer values, converted with int() for existing JSON/.txt storage. Its generator belongs to an order-q subgroup of the safe-prime group, where p=2q+1. Registration accepts these library-generated keys and the earlier full-order keys. Existing keys are reused, not regenerated.

PyCryptodome's public ElGamal sign() method raises NotImplementedError; there is no usable public matching signature API. DS_Sign and DS_Verify therefore retain the textbook equations, using Crypto.Hash.SHA256 for their digest. They do not call the library's private _sign/_verify methods. Standard Python still handles menus, files, JSON, constant-time comparisons, login tokens and modular arithmetic where appropriate.

## Every function: inputs, operation, outputs and usage

### `Canonical(value)`

Input: JSON-compatible value. Sort keys and encode consistently as UTF-8.
Output: bytes. Use Canonical(package) identically before hashing, signing and verification.

### `Write_Text(path, text, private=False)`

Input: destination Path, text str and private flag. Save a UTF-8 .txt file.
Output: None. Private files get owner-only permissions; public artifacts use normal permissions.
Use Write_Text(STORE / 'identities/alice/private_key.txt', json_text, True).

### `Read_Text(path)`

Input: text-file Path. Read UTF-8 without changing its contents. Output: str or file error.

### `Generate_Receiver_Keys(bits=2048)`

Input: RSA modulus bits, default 2048. Generate matching receiver private/public keys together.
Output: (private PEM str, public PEM str). Use the public key to wrap AES, private to unwrap.

### `Generate_Sender_Keys(bits=256)`

Input: ElGamal modulus bits, default 256 for quick practice (not a production size).
Let Crypto.PublicKey.ElGamal.generate create p,g,x,y using secure random bytes.
Output: (private dict {p,g,x}, public dict {p,g,y}); int() makes library values JSON-compatible.
Use Generate_Sender_Keys(2048) when the exam requires a larger modulus.

### `Generate_Symmetric_Key()`

Input: none. Generate fresh 32 random bytes. Output: AES-256 key bytes; use once per message.

### `Encrypt(plaintext, key, aad)`

Input: plaintext bytes, AES key bytes and metadata bytes as AAD.
Encrypt using AES-256-GCM with fresh 12-byte nonce. Output: hex dict ciphertext/nonce/tag.
Use Encrypt(text.encode(), key, Canonical(metadata)); caller saves all three outputs.

### `Decrypt(envelope, key, aad)`

Input: hex envelope dict, recovered AES key, identical metadata bytes.
Verify GCM tag and decrypt. Output: authenticated plaintext bytes; ValueError on altered data.
Never return a plaintext obtained without the tag check.

### `Encrypt_Key(key, receiver_public)`

Input: AES key bytes and receiver public PEM str. RSA-OAEP/SHA-256 encrypt only that key.
Output: encrypted key hex str. Use Encrypt_Key(key, receiver_public); not for encrypting files.

### `Decrypt_Key(encrypted_key, receiver_private)`

Input: encrypted key hex str and matching receiver private PEM str.
RSA-OAEP/SHA-256 unwraps AES key. Output: original key bytes or ValueError on failure.

### `DS_Sign(data, private)`

Input: canonical package bytes and ElGamal private dict {p,g,x}.
Public ElGamal.sign() is unimplemented; apply the signature equations here.
Hash bytes with SHA-256; choose fresh k coprime to p-1; compute r=g^k, s=(h-x*r)/k mod p-1.
Output: dict {r,s}. Never reuse k. Use DS_Sign(Canonical(package), sender_private).

### `DS_Verify(data, signature, public)`

Input: package bytes, signature {r,s}, trusted public dict {p,g,y}.
Compare g^SHA256(data) with y^r*r^s modulo p. Output: bool; no private key/plaintext needed.

### `Hash_Generate(data)`

Input: bytes. Calculate SHA-256. Output: 64-character hex digest str; use on canonical package.

### `Hash_Check(data, expected)`

Input: package bytes and saved hex digest. Recompute and compare. Output: bool.
A hash alone does not authenticate data; signature verification must also succeed.

### `Public_Fingerprint(public, kind)`

Input: public ElGamal dict or RSA PEM, and 'sender'/'receiver'. Output: SHA-256 identifier.
RSA is normalized to DER; ElGamal uses sorted JSON. Private values must never be passed here.

### `Metadata(record_id, sender, receiver, sender_public, receiver_public)`

Input: ID, two usernames and registered public keys. Output: immutable public metadata dict.
Its identities/algorithm labels/fingerprints are covered by the signature and GCM AAD.

### `Create_Packet(text, record_id, sender, receiver, sender_private, sender_public, receiver_public)`

Input: plaintext str, IDs, sender private/public key and receiver public key.
Output: (packet dict, fresh AES key bytes). Encrypt/sign/hash locally; no private key enters packet.

### `Verify_Packet(packet, sender_public, receiver_public)`

Input: packet plus independently trusted sender/receiver public keys. Output: boolean checks.
Verify identities/metadata/signature/hash; malformed artifacts yield overall=False, never plaintext.

### `Save_Packet(packet, folder)`

Input: packet and destination Path. Output: None. Save each artifact separately in .txt files.
Contains only encrypted/public data: ciphertext, nonce, tag, wrapped key, metadata, keys, DS, hash.

### `Read_Packet(folder)`

Input: artifact folder Path. Output: reconstructed packet; missing/malformed files raise errors.

### `Atomic_Text(path, text, private=True)`

Input: .txt Path, text and private flag. Write temporary .txt file then replace target.
Output: None. Protects a single file from partial writes; program handles one operation at a time.

### `Root_Sign(value)`

Input: JSON value. Sign canonical bytes with application audit/storage RSA-PSS/SHA-256 key.
Output: hex signature str. This application key is separate from sender ElGamal/receiver RSA keys.

### `Root_Verify(value, signature)`

Input: JSON value and hex signature. Verify against loaded application root public key.
Output: bool; altered user roles, catalog or audit snapshots cannot be accepted.

### `Signed_Save(name, payload)`

Input: fixed application .txt filename and JSON payload. Sign and atomically save. Output: None.

### `Signed_Read(path)`

Input: signed .txt Path. Verify snapshot signature before use. Output: payload or ValueError.

### `Audit_Read(path=None)`

Input: optional audit-copy Path. Verify snapshot and every sequence/hash-chain link.
Output: event list. Alteration/reordering/tail deletion fails unless an old whole signed snapshot is replayed.

### `Audit(actor, action, details)`

Input: actor, event name and non-secret details. Append timestamped event and sign snapshot.
Output: None. Never include passwords, session tokens, plaintext or private/AES keys.

### `Password_Verifier(password, salt)`

Input: password str and salt hex. Run scrypt N=16384,r=8,p=1. Output: hex verifier, never password.

### `Credential(password, role)`

Input: password >=8 characters and recognized role. Output: salted credential/public-key entry.

### `Setup(admin_password)`

Input: first admin login password, at least eight characters. First run only.
Create application signing keys and signed users/catalog/audit .txt files. Output: None.
The application's private signing key is an owner-only local teaching file; no extra unlock password.

### `Load_State()`

Input: none. Load existing application signing key, validate matching public key and signed files.
Output: None. Accounts and records persist; old login tokens are cleared on restart.

### `Configure_Logging()`

Input: none. Attach local operational .txt log handler once. Output: None; excludes passwords and plaintext.

### `Login(username, password)`

Input: credentials entered at login. Verify signed users DB and scrypt; throttle repeated failures.
Output: token, role, username; token exists only in program memory and expires after 30 minutes.

### `Require(token, permission=None)`

Input: opaque token and required permission. Resolve current enabled account and role inside the program.
Output: (username,user). Raise on missing/expired session, disabled account or unauthorized operation.

### `Manage_User(token, username, password=None, role=None, disable=False)`

Input: admin token and target username; create with password/role or disable=True.
Output: None. Signed role storage prevents raw edits; disabling invalidates target's sessions.

### `Register_Key(token, public)`

Input: sender/receiver session and public key only. Bind first key to authenticated identity.
Output: fingerprint. Existing keys cannot be silently replaced; private values are rejected.

### `Receiver_Key(token, receiver)`

Input: sender session and receiver username. Output: registered enabled receiver's public RSA PEM.

### `Catalog(actor)`

Input: actor name. Verify signed manifest that binds IDs, recipients and complete packet digests.
Output: catalog dict; audit detection/refuse if modified. Never trust folder names alone.

### `Can_Access(username, user, entry)`

Input: authenticated name/user and catalog entry. Output: bool for record-level visibility.

### `Get_Entry(token, record_id, permission)`

Input: session, record ID and permission. Enforce role plus record ownership. Output: (actor,entry).

### `Check_Stored(record_id, entry, folder=None)`

Input: ID, signed catalog entry, optional practice-copy folder. Output: verification dictionary.
Bind packet digest and metadata to manifest and currently registered public keys; catch corrupt files.

### `Submit(token, packet)`

Input: sender session and encrypted/public packet. Validate identity, keys, signatures and ID.
Output: accepted record ID. Store .txt artifacts under a unique ID; no plaintext is stored with public artifacts.

### `List_Records(token)`

Input: authenticated session. Output: visible IDs, metadata summary and integrity status.
Senders see own records; receivers addressed records; admin/reviewer see all, never plaintext.

### `Verify_Record(token, record_id)`

Input: authorized session and ID. Output: all public integrity checks; audit any detected tampering.

### `Tamper_Test(token, record_id, target)`

Input: admin session, existing ID, target artifact or 'audit'. Modify only a practice copy.
Output: expected rejection checks. Never re-sign the changed copy or damage the live original.

### `Audit_Report(token)`

Input: admin session. Output: verified audit snapshot and last 100 operational log lines.
Operational logs are diagnostic, not signed; the signed audit is the integrity-protected record.

### `User_Folder(username)`

Input: account username. Validate safe characters. Output: local identity directory Path.
A username cannot select an arbitrary disk path; only letters/digits/underscore are accepted.

### `Ensure_User_Keys(token)`

Input: sender/receiver login token. Generate/load that user's matching key pair and register public.
Output: public key. First login creates sender ElGamal or receiver RSA keys in separate .txt files.
Existing registered keys with missing private files must be restored, never silently replaced.

### `Save_Message(token, receiver, record_id, plaintext)`

Input: sender token, recipient username, unique record ID, plaintext str. Output: acceptance dict.
Read sender key, get receiver public key, encrypt/hash/sign and save only verified encrypted artifacts.
Save latest sender AES key separately in its private identity folder; receiver never reads that file.

### `Decrypt_Record(token, record_id)`

Input: receiver login token and addressed record ID. Check ownership/hash/signature/metadata.
Output: plaintext str after RSA key unwrapping and GCM authentication; no plaintext is stored.
Refuse unauthorized/tampered records; audit successful decryption or cryptographic rejection.

### `Logout(token)`

Input: active login token. Remove session and audit logout. Output: None; old token stops working.

### `Manage_Users(token)`

Input: admin token and submenu input. Create/disable/list users using guarded functions.
Output: printed results; roles and password verifiers remain in signed users.txt.

### `Role_Menu(token)`

Input: login token and choices. Dispatch compact role menu through permission-checked functions.
Output: None. Role choices do not grant authority; each operation checks the token independently.

### `Menu()`

Input: first-run admin password, later login credentials and role choices. Output: None.
Create/load persistent state, log in, auto-create account keys if needed, then open role menu.
No sockets, separate processes, manual crypto menus or command-line flags are involved.

