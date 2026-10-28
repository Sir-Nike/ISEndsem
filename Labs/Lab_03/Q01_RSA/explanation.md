# Lab 3 Q1: RSA encryption

## What the manual asks

Encrypt/decrypt Asymmetric Encryption using RSA public/private keys.

## Start here: the idea in plain English

Generate an RSA key pair, extract its public key, encode the message, encrypt using OAEP, and decrypt with the private key. OAEP is randomized padding, so encrypting the same message twice normally gives different ciphertext. Print n and e to connect the library operation to the mathematics.

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
    """Input: message and RSA key size. Generate keys and perform RSA-OAEP round trip.
    Output: public parameters, ciphertext and verified recovered text.
    """
    text = ask_text("Message", "Asymmetric Encryption")
    bits = ask_int("RSA key bits", 2048, 2048, 4096)
    key = RSA.generate(bits)
    ciphertext = rsa_encrypt(key.publickey(), text.encode())
    recovered = rsa_decrypt(key, ciphertext)
    print("n:", key.n, "e:", key.e, "Ciphertext:", ciphertext.hex())
    print("Recovered:", recovered.decode(), "Verified:", recovered == text.encode())
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `ask_int(label, default, minimum, maximum)`

Input: prompt, default integer, optional inclusive limits. Read and validate a number.
Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.

### `rsa_encrypt(public_key, message)`

Input: RSA public key and short plaintext bytes. Encrypt using RSA-OAEP/SHA-256.
Output: ciphertext bytes. A 2048-bit key accepts at most 190 plaintext bytes here.

### `rsa_decrypt(private_key, ciphertext)`

Input: RSA private key and OAEP ciphertext. Check padding and recover the message.
Output: plaintext bytes, or ValueError on invalid ciphertext/key. Use with rsa_encrypt.

### `exercise()`

Input: message and RSA key size. Generate keys and perform RSA-OAEP round trip.
Output: public parameters, ciphertext and verified recovered text.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

This is a small, readable teaching program. Its printed intermediate values help you understand the algorithm. Real systems should avoid printing secret keys or sensitive plaintext.
