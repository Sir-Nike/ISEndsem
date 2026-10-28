# Lab 1 additional Q2: Chosen-plaintext transposition attack

## What the manual asks

Eve enters abcdefghi and observes CABDEHFGL. Identify the attack and permutation-key size.

## Start here: the idea in plain English

This is a chosen-plaintext attack because Eve selects the input. A pure transposition must preserve the exact character counts. The supplied output contains L and omits I, so it cannot be a permutation of ABCDEFGHI. Report that inconsistency. A corrected example CABDEHFGI reveals a candidate nine-position mapping, but one example alone does not establish the unique minimal repeated block size.

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
    """Input: chosen plaintext and observed output. Identify attack and check the mapping.
    Output: a permutation if valid, or a clear explanation of the manual's inconsistency.
    """
    plain = ask_text("Chosen plaintext", "abcdefghi").upper()
    cipher = ask_text("Observed output", "CABDEHFGL").upper()
    print("Attack: chosen plaintext. Observed input length:", len(plain))
    try:
        print("Candidate full-block key:", infer_permutation(plain, cipher))
    except ValueError as error:
        print(error)
    print(
        "Corrected illustration ABCDEFGHI -> CABDEHFGI:",
        infer_permutation("ABCDEFGHI", "CABDEHFGI"),
    )
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `infer_permutation(plain, cipher)`

Input: equal-length texts with distinct symbols. Recover output-to-input positions.
Output: 1-based permutation list. Reject inconsistent counts or repeated input symbols.

### `exercise()`

Input: chosen plaintext and observed output. Identify attack and check the mapping.
Output: a permutation if valid, or a clear explanation of the manual's inconsistency.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

This is a small, readable teaching program. Its printed intermediate values help you understand the algorithm. Real systems should avoid printing secret keys or sensitive plaintext.
