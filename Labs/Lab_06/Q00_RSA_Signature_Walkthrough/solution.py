# Lab 6 walkthrough: RSA digital signatures
# Educational lab exercise. No user-defined classes are used.



def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


from Crypto.Signature import pkcs1_15


def sign_message(private_key, message):
    """Input: RSA private key and message bytes. Hash with SHA-256 and sign with PKCS#1 v1.5.
    Output: signature bytes. Use verify_message with the corresponding public key.
    """
    return pkcs1_15.new(private_key).sign(SHA256.new(message))


def verify_message(public_key, message, signature):
    """Input: RSA public key, message bytes and signature bytes. Verify the SHA-256 signature.
    Output: True for a valid signature, False for altered message/signature or wrong key.
    """
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(message), signature)
        return True
    except (ValueError, TypeError):
        return False


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


def main():
    """Input: terminal choices. Run the exercise safely.
    Output: printed results. Use python solution.py and choose a menu option.
    """
    while True:
        print("\n1. Run exercise (you can change the inputs)\n0. Exit")
        choice = input("Choice: ").strip()
        if choice == "0":
            return
        if choice != "1":
            print("Choose 1 or 0.")
            continue
        try:
            exercise()
        except (ValueError, TypeError, KeyError, OSError) as error:
            print("Could not complete operation:", error)


if __name__ == "__main__":
    main()
