# Lab 3: ECC encryption of Secure Transactions

## What the manual asks

Encrypt/decrypt Secure Transactions using elliptic-curve public/private keys.

## Start here: the idea in plain English

ECC is a family of public-key techniques rather than a drop-in block cipher. Generate a P-256 recipient key and a fresh ephemeral sender key. Both sides can compute the same ECDH point. Hash its x-coordinate to get an AES-256 key, then encrypt with AES-GCM. Store the ephemeral public point, nonce and tag with the ciphertext.

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
    """Input: text message. Demonstrate P-256 ECDH plus AES-GCM encryption.
    Output: serialized encrypted record and recovered text; private scalar stays local.
    """
    text = ask_text("Message", "Secure Transactions")
    key = ECC.generate(curve="P-256")
    encrypted = ecc_encrypt(key.public_key(), text.encode())
    recovered = ecc_decrypt(key, encrypted)
    print("Public point:", point_record(key.pointQ))
    print("Encrypted record:", json.dumps(encrypted, indent=2))
    print("Recovered:", recovered.decode(), "Verified:", recovered == text.encode())
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `seal(data, key)`

Input: plaintext bytes and AES key. Encrypt and authenticate using AES-GCM.
Output: dictionary containing nonce, tag and ciphertext as hex strings for JSON storage.

### `open_seal(record, key)`

Input: GCM record and matching AES key. Verify the tag while decrypting.
Output: plaintext bytes. Wrong keys or modified data raise ValueError.

### `point_record(point)`

Input: a PyCryptodome ECC point. Convert public coordinates to JSON-safe integers.
Output: dictionary with x and y. Use to serialize ephemeral public points.

### `read_point(record)`

Input: dictionary of P-256 public coordinates. Validate and construct the point.
Output: ECC point. Use only with records produced for the same curve.

### `ecc_encrypt(public_key, data)`

Input: recipient P-256 public key and plaintext bytes. Derive an AES key with ephemeral ECDH.
Output: JSON-safe GCM record plus ephemeral public point. Use ecc_decrypt to recover it.

### `ecc_decrypt(private_key, record)`

Input: recipient P-256 private key and hybrid encrypted record. Recreate ECDH key.
Output: verified plaintext bytes. Uses the ephemeral public point stored in the record.

### `exercise()`

Input: text message. Demonstrate P-256 ECDH plus AES-GCM encryption.
Output: serialized encrypted record and recovered text; private scalar stays local.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

secp256r1 and NIST P-256 name the same curve. This explicitly implements hybrid ECC encryption, since a curve alone does not define a message-encryption scheme.
