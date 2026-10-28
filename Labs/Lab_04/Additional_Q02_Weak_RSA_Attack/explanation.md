# Lab 4 additional Q2: Attack weak RSA primes

## What the manual asks

Demonstrate recovery of a vulnerable RSA private key when its prime factors are too small or insufficiently random, and discuss mitigation.

## Start here: the idea in plain English

The question does not specify which private-key bits were leaked, so implement the concrete weakness it does specify: factor a toy modulus built from small primes. Trial division recovers p and q. Compute phi and the inverse of e to reconstruct d, then decrypt the intercepted ciphertext. The attacker function receives only n, e and ciphertext, not the private factors.

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
    """Input: weak primes and a message integer. Simulate interception and factor the public modulus.
    Output: recovered factors/private exponent, plaintext and suggested key-generation fixes.
    """
    p = ask_int("Small prime p", 1009, 3, 1000000)
    q = ask_int("Small prime q", 1013, 3, 1000000)
    if p == q or not isPrime(p) or not isPrime(q):
        raise ValueError("Use distinct primes.")
    n = p * q
    e = 65537
    if math.gcd(e, (p - 1) * (q - 1)) != 1:
        raise ValueError("Choose different primes for e=65537.")
    message = ask_int("Message integer", 123, 0, n - 1)
    ciphertext = pow(message, e, n)
    d, recovered, factors = attack_rsa(n, e, ciphertext)
    print(
        "Intercepted n,e,c:",
        n,
        e,
        ciphertext,
        "Recovered p,q:",
        factors,
        "d:",
        d,
        "Message:",
        recovered,
    )
    print("Verified:", recovered == message)
    print(
        "Mitigation: library-generated RSA-2048+ keys, cryptographic randomness, distinct independent primes, protect private keys, OAEP for encryption."
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

### `factor_small_modulus(n, limit)`

Input: RSA modulus and trial-division bound. Search for a small factor.
Output: (p,q), or ValueError when no factor is found within this educational bound.

### `attack_rsa(n, e, ciphertext)`

Input: public n/e and ciphertext integer. Factor weak n and reconstruct the private exponent.
Output: recovered d, decrypted integer and factors. Use only deliberately weak examples.

### `exercise()`

Input: weak primes and a message integer. Simulate interception and factor the public modulus.
Output: recovered factors/private exponent, plaintext and suggested key-generation fixes.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

No exact partial-private-key leakage model is supplied, so this does not claim to implement a specialized partial-key exposure attack. It demonstrates the stated weak-factor vulnerability. Trial division is bounded to avoid hanging on large public keys.
