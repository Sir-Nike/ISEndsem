# Lab 1 additional Q3: Vigenere with HEALTH

## What the manual asks

Encrypt "Life is full of surprises" with keyword HEALTH.

## Start here: the idea in plain English

Normalize to letters, repeat HEALTH, and add key-letter values modulo 26. Subtract those values to check the result.

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
    """Input: message and keyword. Demonstrate Vigenere encryption and decryption.
    Output: ciphertext and recovered letters. Defaults use the additional exercise values.
    """
    text = ask_text("Message", "Life is full of surprises")
    key = ask_text("Keyword", "HEALTH")
    ciphertext = vigenere(text, key)
    print("Ciphertext:", ciphertext, "Recovered:", vigenere(ciphertext, key, True))
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `letters(text)`

Input: any string. Keep only English A-Z letters and uppercase them.
Output: normalized text. Use before a classical cipher; spaces are discarded.

### `vigenere(text, keyword, decrypt)`

Input: text and nonempty keyword. Add repeating key letters modulo 26.
Output: encrypted or recovered letters. Set decrypt=True to subtract the key.

### `exercise()`

Input: message and keyword. Demonstrate Vigenere encryption and decryption.
Output: ciphertext and recovered letters. Defaults use the additional exercise values.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

This is a small, readable teaching program. Its printed intermediate values help you understand the algorithm. Real systems should avoid printing secret keys or sensitive plaintext.
