# Lab 3 Q4: RSA versus ECC secure file transfer

## What the manual asks

Implement file transfer with RSA-2048 and ECC secp256r1; compare 1 MB and 10 MB files, key generation, encryption/decryption and overhead.

## Start here: the idea in plain English

Large files are encrypted with AES-GCM. RSA-OAEP wraps the AES key; ECC uses ephemeral ECDH to derive it. Write the encrypted envelope to a file, read it back, decrypt into a recovered file and verify exact byte equality. Compare key sizes and end-to-end times; JSON hex encoding deliberately adds storage overhead.

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
    """Input: comma-separated file sizes in bytes. Run both hybrid transfer benchmarks.
    Output: timings and transfer_output files beside this script; verify recovery.
    """
    sizes = [
        int(x) for x in ask_text("Sizes in bytes, comma separated", "1048576,10485760").split(",")
    ]
    if not sizes or any(n < 1 or n > 20 * 1024 * 1024 for n in sizes):
        raise ValueError("Use sizes in 1..20971520 bytes.")
    compare_files(sizes, Path(__file__).resolve().parent / "transfer_output")
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

### `compare_files(sizes, folder)`

Input: list of byte counts and output directory. Benchmark RSA/ECC hybrid file transfer.
Output: measurements printed and encrypted/recovered files saved; verify every byte.

### `exercise()`

Input: comma-separated file sizes in bytes. Run both hybrid transfer benchmarks.
Output: timings and transfer_output files beside this script; verify recovery.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

RSA cannot directly encrypt a 1 MB file. Hybrid encryption is necessary here. Timing includes some file/JSON work as shown in the function. The standalone solution simulates transfer through stored envelopes; the additional server.py/client.py perform actual TCP file transfer. The simulated benchmark shares recipient key material inside one process.


## Real client/server file transfer

The benchmark solution remains `solution.py`. For real localhost TCP transfer, use the additional `server.py` and `client.py`:

1. Terminal 1: run `../../../.venv/bin/python server.py`, choose 1, accept localhost/5034 and 4 transfers.
2. Terminal 2: run `../../../.venv/bin/python client.py`, choose 1, accept localhost/5034, generated data, sizes 1048576 and 10485760, and schemes RSA,ECC.
3. Four encrypted file envelopes cross the TCP connection. The receiver saves recovered files and returns their SHA-256 digests; the client verifies lengths/digests. Each side reports timings.
4. Choose 0 when finished. You may instead supply a real input file path and adjust the server transfer count.

The receiver sends its public key first. This localhost exercise assumes the selected server is trusted; an untrusted network requires authenticating that public key through a certificate or known fingerprint. Large ciphertexts are sent as bounded chunks, so 10 MB files do not exceed the per-frame JSON limit.

### server.py functions

**ask_text**: Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

**ask_int**: Input: prompt, default integer, optional inclusive limits. Read and validate a number.
Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.

**rsa_decrypt**: Input: RSA private key and OAEP ciphertext. Check padding and recover the message.
Output: plaintext bytes, or ValueError on invalid ciphertext/key. Use with rsa_encrypt.

**open_seal**: Input: GCM record and matching AES key. Verify the tag while decrypting.
Output: plaintext bytes. Wrong keys or modified data raise ValueError.

**read_point**: Input: dictionary of P-256 public coordinates. Validate and construct the point.
Output: ECC point. Use only with records produced for the same curve.

**ecc_decrypt**: Input: recipient P-256 private key and hybrid encrypted record. Recreate ECDH key.
Output: verified plaintext bytes. Uses the ephemeral public point stored in the record.

**rsa_hybrid_decrypt**: Input: RSA private key and hybrid record. Unwrap the AES key and verify/decrypt data.
Output: original plaintext bytes. Use with rsa_hybrid_encrypt.

**receive_exact**: Input: connected socket and required byte count. Read until all bytes arrive.
Output: bytes of exactly count length. Raise ValueError if the peer disconnects early.

**send_json**: Input: connected socket and JSON-compatible record. Prefix UTF-8 JSON with a 4-byte length.
Output: bytes sent over TCP; returns nothing. Framing handles TCP splitting/coalescing.

**receive_json**: Input: connected socket. Read bounded length-prefixed JSON, including partial TCP reads.
Output: parsed JSON value. Reject frames over 2 MB before allocating their payload.

**receive_file**: Input: connected client and output directory. Exchange public key, receive encrypted chunks and decrypt.
Output: stored recovered file and a digest/timing reply; no plaintext file contents cross TCP.

**exercise**: Input: host/port and number of files to accept. Run the RSA/ECC encrypted file receiver.
Output: decrypted files in received_files and per-transfer timing/digest responses.

**main**: Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

### client.py functions

**ask_text**: Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

**ask_int**: Input: prompt, default integer, optional inclusive limits. Read and validate a number.
Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.

**rsa_encrypt**: Input: RSA public key and short plaintext bytes. Encrypt using RSA-OAEP/SHA-256.
Output: ciphertext bytes. A 2048-bit key accepts at most 190 plaintext bytes here.

**seal**: Input: plaintext bytes and AES key. Encrypt and authenticate using AES-GCM.
Output: dictionary containing nonce, tag and ciphertext as hex strings for JSON storage.

**point_record**: Input: a PyCryptodome ECC point. Convert public coordinates to JSON-safe integers.
Output: dictionary with x and y. Use to serialize ephemeral public points.

**ecc_encrypt**: Input: recipient P-256 public key and plaintext bytes. Derive an AES key with ephemeral ECDH.
Output: JSON-safe GCM record plus ephemeral public point. Use ecc_decrypt to recover it.

**rsa_hybrid_encrypt**: Input: RSA public key and arbitrary-length data. AES-GCM encrypt data and wrap its key.
Output: JSON-safe encrypted record. RSA handles only the small AES key, not the whole file.

**receive_exact**: Input: connected socket and required byte count. Read until all bytes arrive.
Output: bytes of exactly count length. Raise ValueError if the peer disconnects early.

**send_json**: Input: connected socket and JSON-compatible record. Prefix UTF-8 JSON with a 4-byte length.
Output: bytes sent over TCP; returns nothing. Framing handles TCP splitting/coalescing.

**receive_json**: Input: connected socket. Read bounded length-prefixed JSON, including partial TCP reads.
Output: parsed JSON value. Reject frames over 2 MB before allocating their payload.

**transfer_file**: Input: server address, RSA/ECC selection and plaintext file bytes. Encrypt locally and send chunked envelope.
Output: server reply plus local encryption time. Compare plaintext digests to verify exact recovery.

**exercise**: Input: server address, optional real file path or generated sizes, and scheme list.
Output: real TCP transfers and verified timing rows for RSA/ECC; start server.py first.

**main**: Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.
