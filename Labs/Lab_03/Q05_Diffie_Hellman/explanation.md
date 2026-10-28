# Lab 3 Q5: Diffie-Hellman peer key exchange

## What the manual asks

Implement peer-to-peer Diffie-Hellman and measure key generation and key exchange time.

## Start here: the idea in plain English

Alice chooses a private exponent and publishes g^a; Bob publishes g^b. Alice computes B^a and Bob computes A^b, which are equal modulo p. Hash the shared value to form a symmetric key. Use a standard 2048-bit group and validate received public values.

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
    """Input: none. Generate two peers' keys and derive their shared AES key.
    Output: public values, timing measurements and equality of the derived keys.
    """
    start = time.perf_counter()
    a, A = dh_keypair()
    b, B = dh_keypair()
    generation = time.perf_counter() - start
    start = time.perf_counter()
    alice = dh_shared(a, B)
    bob = dh_shared(b, A)
    exchange = time.perf_counter() - start
    print("Alice public:", A, "Bob public:", B)
    print("Generation seconds:", generation, "Exchange seconds:", exchange)
    print("Demo shared key:", alice.hex(), "Both peers agree:", alice == bob)
    assert alice == bob
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `dh_keypair(p, g)`

Input: prime and generator (standard defaults). Draw a random private exponent.
Output: (private, public=g^private mod p). Only the public value is exchanged.

### `dh_shared(private, peer_public, p)`

Input: own private exponent, peer public value and safe prime. Validate the peer.
Output: SHA-256-derived 32-byte shared key. Both peers get the same key.

### `exercise()`

Input: none. Generate two peers' keys and derive their shared AES key.
Output: public values, timing measurements and equality of the derived keys.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

Diffie-Hellman exchanges a key; it is not a signature or direct message-encryption algorithm. This isolated demonstration has no identity authentication. A complete communication system authenticates public values, as Lab 4 Q1 demonstrates.
