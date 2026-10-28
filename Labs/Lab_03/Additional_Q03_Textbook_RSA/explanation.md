# Lab 3 additional Q3: Textbook RSA with small parameters

## What the manual asks

Encrypt/decrypt Cryptographic Protocols with n=323, e=5, d=173.

## Start here: the idea in plain English

The tiny modulus cannot hold a complete message. Encode UTF-8 one byte at a time and apply pow(byte,e,n). Decrypt each integer with pow(cipher,d,n). This is raw textbook RSA, so it is deterministic and is used only to illustrate modular arithmetic.

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
    """Input: message and numeric RSA parameters. Show a small textbook-RSA example.
    Output: ciphertext list and recovered text, with a correctness check.
    """
    text = ask_text("Message", "Cryptographic Protocols")
    n = ask_int("n", 323, 256)
    e = ask_int("e", 5, 2)
    d = ask_int("d", 173, 2)
    ciphertext = textbook_encrypt(text.encode(), n, e)
    recovered = textbook_decrypt(ciphertext, n, d)
    print(
        "Ciphertext:",
        ciphertext,
        "Recovered:",
        recovered.decode(),
        "Verified:",
        recovered == text.encode(),
    )
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `ask_int(label, default, minimum, maximum)`

Input: prompt, default integer, optional inclusive limits. Read and validate a number.
Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.

### `textbook_encrypt(data, n, e)`

Input: plaintext bytes, modulus and public exponent. Encrypt each byte separately.
Output: list of ciphertext integers. Modulus must exceed all byte values.

### `textbook_decrypt(ciphertext, n, d)`

Input: ciphertext integer list, modulus and private exponent. Decrypt each integer.
Output: recovered bytes; invalid/inconsistent key values may fail byte conversion.

### `exercise()`

Input: message and numeric RSA parameters. Show a small textbook-RSA example.
Output: ciphertext list and recovered text, with a correctness check.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

n=323=17*19 and phi(n)=288; 5*173 is 1 modulo 288. Raw byte-wise RSA provides no practical message security. Ordinary RSA examples use OAEP instead.
