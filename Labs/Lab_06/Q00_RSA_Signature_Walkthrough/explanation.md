# Lab 6 walkthrough: RSA digital signatures

## What the manual asks

Generate RSA keys, sign a document, verify it, produce a response signature and reject tampering.

## Start here: the idea in plain English

Alice and Bob each generate their own RSA key pair. Signing hashes the document with SHA-256 and signs using the private key. Verification recomputes the hash and checks the signature with the signer's public key. Changing the message or using a different signer's key must fail. Private keys never need to be exchanged.

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
    """Input: Alice document and Bob reply. Sign/verify each using separate RSA identities.
    Output: signatures and valid/tampered/wrong-signer verification results.
    """
    alice = RSA.generate(2048)
    bob = RSA.generate(2048)
    document = ask_text("Alice document", "Alice approves this legal document").encode()
    signature = sign_message(alice, document)
    print("Alice signature:", signature.hex())
    print("Bob verifies Alice:", verify_message(alice.publickey(), document, signature))
    print("Tampered document:", verify_message(alice.publickey(), document + b"!", signature))
    print("Wrong signer:", verify_message(bob.publickey(), document, signature))
    response = ask_text("Bob response", "BOB accepts the document").encode()
    reply_signature = sign_message(bob, response)
    print(
        "Bob signature:",
        reply_signature.hex(),
        "Alice verifies Bob:",
        verify_message(bob.publickey(), response, reply_signature),
    )
```

Follow the calls in `exercise()` from top to bottom. It obtains the inputs, calls the small functions that do the work, and prints intermediate values and the final result. Bytes are shown as hexadecimal when ordinary text would be unreadable. A successful round trip prints a recovered message equal to the input; verification examples also show a changed message being rejected where applicable.

## Every function explained

### `ask_text(label, default)`

Input: a prompt and default string. Read text, or use the default when Enter is pressed.
Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.

### `sign_message(private_key, message)`

Input: RSA private key and message bytes. Hash with SHA-256 and sign with PKCS#1 v1.5.
Output: signature bytes. Use verify_message with the corresponding public key.

### `verify_message(public_key, message, signature)`

Input: RSA public key, message bytes and signature bytes. Verify the SHA-256 signature.
Output: True for a valid signature, False for altered message/signature or wrong key.

### `exercise()`

Input: Alice document and Bob reply. Sign/verify each using separate RSA identities.
Output: signatures and valid/tampered/wrong-signer verification results.

### `main()`

Input: terminal choices. Run the exercise safely.
Output: printed results. Use python solution.py and choose a menu option.

## What to change during an exam

Change values through the prompts first. For a different scenario, replace the example messages or record fields in `exercise()`, and keep the cryptographic functions. Match the requested algorithm, key size, mode, and hash exactly. Store IVs/nonces alongside ciphertext when needed. Keep private keys private. Hashing cannot be decrypted; encryption can. A hash by itself does not prove who sent a message.

## Notes and limitations

The manual website walkthrough asks participants to exchange private keys. That is incorrect for a secure signature workflow: exchange only public keys. This program uses fresh separate identities and PKCS#1 v1.5 signatures rather than reproducing insecure website key handling.
