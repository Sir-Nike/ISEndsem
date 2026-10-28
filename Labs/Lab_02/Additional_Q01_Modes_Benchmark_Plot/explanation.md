# Lab 2 additional Q1: Compare modes and plot timings

## What the manual asks

Encrypt five messages using DES and AES-128/192/256, compare operation modes, and plot execution time.

## Start here: the idea in plain English

Generate one key per algorithm/key-size combination and reuse it across five messages, with a fresh IV or nonce for each encryption. Benchmark ECB, CBC, CFB, OFB and CTR. Save a CSV table and an SVG bar chart using only the standard library, so matplotlib is not required.

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
    """Input: repeat count. Benchmark 4 key choices, 5 modes and 5 example messages.
    Output: timing rows, timings.csv and timings.svg beside this script.
    """
    import csv

    repeats = ask_int("Repetitions per measurement", 30, 1, 10000)
    messages = [
        "Hello",
        "Information Security",
        "Five different messages",
        "Mode comparison example",
        "A longer message for the fifth test.",
    ]
    rows = []
    for algorithm, size in [("DES", 8), ("AES", 16), ("AES", 24), ("AES", 32)]:
        key = get_random_bytes(size)
        for mode in ("ECB", "CBC", "CFB", "OFB", "CTR"):
            for message in messages:
                enc, dec = benchmark(message, key, algorithm, mode, repeats)
                rows.append((algorithm + "-" + str(size * 8), mode, message, enc, dec))
    base = Path(__file__).resolve().parent
    with (base / "timings.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["algorithm", "mode", "message", "encrypt_us", "decrypt_us"])
        writer.writerows(rows)
    save_chart(rows, base / "timings.svg")
    for label, mode, message, enc, dec in rows:
        print(label, mode, repr(message), round(enc, 2), round(dec, 2), "us")
    print("Saved:", base / "timings.csv", base / "timings.svg")
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `ask_int(label, default, minimum, maximum)`

Input: prompt, default integer, optional inclusive limits. Read and validate a number.
Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.

### `encrypt_bytes(data, key, algorithm, mode, parameter)`

Input: plaintext bytes, key bytes, algorithm, mode, optional IV/nonce.
Output: (IV-or-nonce, ciphertext). Pad ECB/CBC; CTR/CFB/OFB accept any byte length.
Use the returned parameter unchanged when decrypting.

### `decrypt_bytes(parameter, ciphertext, key, algorithm, mode)`

Input: stored IV/nonce, ciphertext, original key, algorithm and mode.
Output: recovered plaintext bytes. Use exactly the same settings as encryption.

### `benchmark(message, key, algorithm, mode, repeats)`

Input: text, key, algorithm, mode and positive repeat count. Time complete operations.
Output: average encryption and decryption microseconds; setup and padding are included.

### `save_chart(rows, path)`

Input: benchmark tuples and output path. Draw average encryption times as SVG bars.
Output: saved SVG file. Open it in any browser to compare combinations visually.

### `exercise()`

Input: repeat count. Benchmark 4 key choices, 5 modes and 5 example messages.
Output: timing rows, timings.csv and timings.svg beside this script.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

This is a small, readable teaching program. Its printed intermediate values help you understand the algorithm. Real systems should avoid printing secret keys or sensitive plaintext.
