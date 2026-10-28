# Lab 3 Q3: ElGamal encryption

## What the manual asks

Encrypt/decrypt Confidential Data using public parameters (p,g,h) and private exponent x.

## Start here: the idea in plain English

Generate a safe-prime demonstration key. For each encoded byte choose a fresh random exponent, compute two ciphertext components, and decrypt using a modular inverse. Shift byte values by one to keep messages nonzero. A list of pairs represents the whole message.

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
    """Input: message and modulus size. Generate ElGamal parameters and encrypt each byte.
    Output: public parameters, ciphertext pairs, recovered message and verification.
    """
    text = ask_text("Message", "Confidential Data")
    bits = ask_int("Demo modulus bits", 256, 32, 2048)
    public, private = elgamal_keys(bits)
    ciphertext = elgamal_text_encrypt(public, text)
    recovered = elgamal_text_decrypt(public, private, ciphertext)
    print("Public key:", public, "Ciphertext:", ciphertext)
    print("Recovered:", recovered, "Verified:", recovered == text)
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `ask_int(label, default, minimum, maximum)`

Input: prompt, default integer, optional inclusive limits. Read and validate a number.
Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.

### `elgamal_keys(bits)`

Input: demonstration modulus bit size. Generate safe prime p=2q+1 and subgroup generator.
Output: (public dictionary p,g,y; private x). Use 2048+ bits for serious parameters.

### `elgamal_encrypt(public, message)`

Input: ElGamal public parameters and integer 1<=message<p. Randomize and encrypt.
Output: pair (g^k mod p, message*y^k mod p). Use fresh k for every encryption.

### `elgamal_decrypt(public, private, ciphertext)`

Input: public parameters, private exponent and ciphertext pair. Remove the shared mask.
Output: original integer. Multiply c2 by the modular inverse of c1^private.

### `elgamal_text_encrypt(public, text)`

Input: public parameters with p>256 and text. Encrypt each UTF-8 byte plus one.
Output: list of ciphertext pairs. Byte-wise encryption is simple but inefficient.

### `elgamal_text_decrypt(public, private, ciphertexts)`

Input: ElGamal keys and list of encrypted byte pairs. Decrypt and undo the +1 mapping.
Output: decoded UTF-8 string. Use with elgamal_text_encrypt.

### `exercise()`

Input: message and modulus size. Generate ElGamal parameters and encrypt each byte.
Output: public parameters, ciphertext pairs, recovered message and verification.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

256-bit finite-field ElGamal is only a quick demonstration size. The curve-based exercises below use P-256 instead. This byte-wise textbook scheme does not authenticate messages.
