# Lab 2 Q5: AES-192 with every round shown

## What the manual asks

Encrypt Top Secret Data using AES-192 and show key expansion, initial round, main rounds and final round.

## Start here: the idea in plain English

AES-192 uses a 24-byte key and 12 rounds. This implementation prints all 13 round keys and the state after each transformation for every padded 16-byte block. It then checks its ciphertext against PyCryptodome AES-ECB and decrypts it. ECB is used here to expose the raw block transformation clearly.

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
    """Input: message and 24-byte key. Trace every AES block and verify with the library.
    Output: key schedule, all round states, ciphertext and recovered original message.
    """
    text = ask_text("Message", "Top Secret Data")
    key = parse_key(
        ask_text("AES-192 key", "hex:FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"), "AES"
    )
    if len(key) != 24:
        raise ValueError("This exercise specifically needs a 24-byte key.")
    data = pad(text.encode(), 16)
    output = b""
    for i in range(0, len(data), 16):
        print("Block", i // 16 + 1)
        output += encrypt_block_trace(data[i : i + 16], key)
    expected = AES.new(key, AES.MODE_ECB).encrypt(data)
    assert output == expected
    print("Ciphertext:", output.hex(), "Library agrees:", output == expected)
    print("Recovered:", unpad(AES.new(key, AES.MODE_ECB).decrypt(output), 16).decode())
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `parse_key(text, algorithm)`

Input: key written as hex:... or text:..., plus AES/DES/3DES algorithm name.
Output: validated key bytes. Explicit prefixes prevent hex text being misread as ASCII.

### `gf_multiply(a, b)`

Input: two bytes as integers. Multiply in AES's GF(2^8) using polynomial 0x11b.
Output: one byte integer. Used by the S-box construction and MixColumns.

### `make_sbox()`

Input: none. Compute each byte's field inverse and AES affine transformation.
Output: 256-entry S-box list. This avoids a long unexplained hardcoded table.

### `expand_key(key, sbox)`

Input: 24-byte AES-192 key and S-box. Expand six initial words into 52 words.
Output: 13 round keys, each 16 bytes. Apply RotWord, SubWord and Rcon every sixth word.

### `encrypt_block_trace(block, key)`

Input: one 16-byte block and 24-byte key. Print AES-192's intermediate states.
Output: 16 ciphertext bytes. State uses AES column-major order; final round omits mixing.

### `exercise()`

Input: message and 24-byte key. Trace every AES block and verify with the library.
Output: key schedule, all round states, ciphertext and recovered original message.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

The manual supplies only 32 hex digits for its AES-192 example, which is not a 24-byte key. This default corrects the length to 48 hex digits. The hand-written trace is educational; use the tested library for ordinary encryption.
