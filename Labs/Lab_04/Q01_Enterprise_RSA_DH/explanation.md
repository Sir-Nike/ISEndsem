# Lab 4 Q1: Enterprise RSA and Diffie-Hellman communication

## What the manual asks

Build secure communication among Finance, HR and Supply Chain, with RSA/DH, key generation/distribution/revocation and support for new subsystems.

## Start here: the idea in plain English

Register each subsystem by name, generating its identity key. Exchange ephemeral DH public values, sign the exchange using RSA, derive a shared key, wrap that key using recipient RSA, and encrypt the document using AES-GCM. Sign the document separately and verify it at the receiver. Registry entries make adding another subsystem straightforward; revoked subsystems cannot send or receive through this program. Register Finance, HR and SupplyChain first, then choose Send.

## How to run

From this question folder, run:

```bash
../../../.venv/bin/python solution.py
```

The program is interactive. If you installed dependencies into another environment, use that environment's Python instead. Read `Labs/README.md` for setup. Paths above assume the environment is in the project root, beside `Labs`.

Press 1 to run an exercise, enter your values or press Enter for the displayed default, and press 0 to exit. Input conversion and validation errors are printed without terminating the interactive menu. Each function can also be imported and called separately.

## Step-by-step solution

1. Start the program and select Run. Read the displayed default inputs before changing them.
2. Follow the input prompts. Text is encoded to bytes when required; numeric inputs are checked before cryptographic operations.
3. Read the `exercise()` function below: it connects the functions in the order needed for this question.
4. Compare the printed output with the expected result, and repeat using a different input.

```python
def exercise():
    """Input: repeated menu choices for subsystem registration, listing, transfer and revocation.
    Output: persisted registry, transfer envelopes, verification and audit entries.
    """
    folder = Path(__file__).resolve().parent / "storage"
    systems = load_systems(folder)
    while True:
        print("\n1 Register subsystem  2 List  3 Send document  4 Revoke  0 Back")
        choice = input("Operation: ").strip()
        if choice == "0":
            return
        try:
            if choice == "1":
                name = ask_text("Subsystem name", "Finance")
                register_system(systems, name)
                save_systems(folder, systems, "registered " + name)
            elif choice == "2":
                print({name: record["active"] for name, record in systems.items()})
            elif choice == "3":
                sender = ask_text("Sender", "Finance")
                recipient = ask_text("Recipient", "HR")
                text = ask_text("Document", "Approved financial report")
                envelope, recovered, valid = transfer_document(
                    systems, sender, recipient, text.encode()
                )
                path = folder / f"transfer_{time.time_ns()}.json"
                path.write_text(json.dumps(envelope, indent=2))
                print(
                    "Stored:", path, "Recovered:", recovered.decode(), "Signature verified:", valid
                )
                save_systems(folder, systems, "document transfer " + sender + " to " + recipient)
            elif choice == "4":
                name = ask_text("Subsystem to revoke", "HR")
                systems[name]["active"] = False
                save_systems(folder, systems, "revoked " + name)
            else:
                print("Invalid choice.")
        except (ValueError, KeyError, OSError) as error:
            print("Operation rejected:", error)
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `rsa_encrypt(public_key, message)`

Input: RSA public key and short plaintext bytes. Encrypt using RSA-OAEP/SHA-256.
Output: ciphertext bytes. A 2048-bit key accepts at most 190 plaintext bytes here.

### `rsa_decrypt(private_key, ciphertext)`

Input: RSA private key and OAEP ciphertext. Check padding and recover the message.
Output: plaintext bytes, or ValueError on invalid ciphertext/key. Use with rsa_encrypt.

### `seal(data, key)`

Input: plaintext bytes and AES key. Encrypt and authenticate using AES-GCM.
Output: dictionary containing nonce, tag and ciphertext as hex strings for JSON storage.

### `open_seal(record, key)`

Input: GCM record and matching AES key. Verify the tag while decrypting.
Output: plaintext bytes. Wrong keys or modified data raise ValueError.

### `dh_keypair(p, g)`

Input: prime and generator (standard defaults). Draw a random private exponent.
Output: (private, public=g^private mod p). Only the public value is exchanged.

### `dh_shared(private, peer_public, p)`

Input: own private exponent, peer public value and safe prime. Validate the peer.
Output: SHA-256-derived 32-byte shared key. Both peers get the same key.

### `sign_message(private_key, message)`

Input: RSA private key and message bytes. Hash with SHA-256 and sign with PKCS#1 v1.5.
Output: signature bytes. Use verify_message with the corresponding public key.

### `verify_message(public_key, message, signature)`

Input: RSA public key, message bytes and signature bytes. Verify the SHA-256 signature.
Output: True for a valid signature, False for altered message/signature or wrong key.

### `load_systems(folder)`

Input: storage directory. Load persisted subsystem keys/status, or start empty.
Output: registry dictionary. This local teaching program protects files by OS permissions.

### `save_systems(folder, systems, event)`

Input: storage directory, registry and audit description. Persist and append audit entry.
Output: updated owner-only JSON and audit log files; returns nothing.

### `register_system(systems, name)`

Input: registry and new subsystem name. Generate RSA-2048 identity/wrapping keys.
Output: updated registry in place. Existing names are rejected to prevent silent overwrites.

### `transfer_document(systems, sender, recipient, message)`

Input: registry, active sender/recipient names and document bytes. Authenticate DH public values with RSA.
Output: JSON-safe encrypted envelope, recovered document and validity result. RSA also wraps the derived AES key.

### `exercise()`

Input: repeated menu choices for subsystem registration, listing, transfer and revocation.
Output: persisted registry, transfer envelopes, verification and audit entries.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

This is an in-process simulation of the endpoints, not a deployed network service. Public-key distribution uses the trusted local registry. Registry private keys are stored in an owner-only file; users with access to the OS account can still read them. Application revocation blocks future operations but cannot erase copies of old keys or plaintext already obtained.
