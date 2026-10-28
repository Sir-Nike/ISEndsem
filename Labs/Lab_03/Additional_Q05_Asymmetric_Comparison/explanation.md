# Lab 3 additional Q5: RSA, curve ElGamal and ECC comparison

## What the manual asks

Compare RSA-2048, ElGamal on secp256r1, and ECC for government messages of 1 KB and 10 KB.

## Start here: the idea in plain English

Compare three complete hybrid constructions: RSA-OAEP plus AES-GCM, EC-ElGamal point encapsulation plus AES-GCM, and ephemeral ECDH plus AES-GCM. Using the same symmetric payload encryption makes the asymmetric overhead visible. Generate keys, encrypt/decrypt the same data, verify recovery and report serialized storage size.

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
    """Input: comma-separated message sizes. Time all three specified hybrid approaches.
    Output: key generation, encryption/decryption times, envelope size and correctness.
    """
    sizes = [int(x) for x in ask_text("Sizes in bytes", "1024,10240").split(",")]
    if any(not 1 <= x <= 10485760 for x in sizes):
        raise ValueError("Sizes must be in 1..10485760.")
    data_by_size = {size: get_random_bytes(size) for size in sizes}
    for name in ("RSA-2048", "EC-ElGamal-P256", "ECDH-P256"):
        start = time.perf_counter()
        key = RSA.generate(2048) if name == "RSA-2048" else ECC.generate(curve="P-256")
        print(name, "key generation s:", time.perf_counter() - start)
        if name == "RSA-2048":
            public, enc, dec = key.publickey(), rsa_hybrid_encrypt, rsa_hybrid_decrypt
        elif name == "EC-ElGamal-P256":
            public, enc, dec = key.public_key(), ec_elgamal_encrypt, ec_elgamal_decrypt
        else:
            public, enc, dec = key.public_key(), ecc_encrypt, ecc_decrypt
        for size, data in data_by_size.items():
            start = time.perf_counter()
            record = enc(public, data)
            encryption = time.perf_counter() - start
            start = time.perf_counter()
            recovered = dec(key, record)
            decryption = time.perf_counter() - start
            assert recovered == data
            print(
                size,
                "bytes; encrypt s:",
                encryption,
                "decrypt s:",
                decryption,
                "stored bytes:",
                len(json.dumps(record).encode()),
                "verified:",
                recovered == data,
            )
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

### `rsa_hybrid_encrypt(public_key, data)`

Input: RSA public key and arbitrary-length data. AES-GCM encrypt data and wrap its key.
Output: JSON-safe encrypted record. RSA handles only the small AES key, not the whole file.

### `rsa_hybrid_decrypt(private_key, record)`

Input: RSA private key and hybrid record. Unwrap the AES key and verify/decrypt data.
Output: original plaintext bytes. Use with rsa_hybrid_encrypt.

### `ec_elgamal_encrypt(public_key, data)`

Input: P-256 public key and bytes. ElGamal-encrypt a random curve point, then use it as AES key material.
Output: JSON-safe C1/C2 points and GCM data. C1=kG and C2=R+kQ hide the random point R.

### `ec_elgamal_decrypt(private_key, record)`

Input: P-256 private key and EC-ElGamal hybrid record. Recover R=C2-private*C1.
Output: authenticated plaintext bytes after deriving the same AES key from R.

### `exercise()`

Input: comma-separated message sizes. Time all three specified hybrid approaches.
Output: key generation, encryption/decryption times, envelope size and correctness.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

The manual loosely mixes curve and finite-field ElGamal terminology. This solution respects its explicit secp256r1 requirement by using the curve version. Timings are measurements, not a universal ranking of algorithms.
