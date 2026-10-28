# Lab 3 Q1: RSA encryption
# Educational lab exercise. No user-defined classes are used.



def ask_text(label, default):
    """Input: a prompt and default string. Read text, or use the default when Enter is pressed.
    Output: a string. Use ask_text('Message', 'hello') to let the user choose a message.
    """
    return input(f"{label} [{default}]: ").strip() or str(default)


def ask_int(label, default, minimum=None, maximum=None):
    """Input: prompt, default integer, optional inclusive limits. Read and validate a number.
    Output: an integer; raise ValueError on bad input. Use for keys, counts, or amounts.
    """
    value = int(ask_text(label, default))
    if minimum is not None and value < minimum:
        raise ValueError(f"{label} must be at least {minimum}.")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} must be at most {maximum}.")
    return value


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


def rsa_encrypt(public_key, message):
    """Input: RSA public key and short plaintext bytes. Encrypt using RSA-OAEP/SHA-256.
    Output: ciphertext bytes. A 2048-bit key accepts at most 190 plaintext bytes here.
    """
    return PKCS1_OAEP.new(public_key, hashAlgo=SHA256).encrypt(message)


def rsa_decrypt(private_key, ciphertext):
    """Input: RSA private key and OAEP ciphertext. Check padding and recover the message.
    Output: plaintext bytes, or ValueError on invalid ciphertext/key. Use with rsa_encrypt.
    """
    return PKCS1_OAEP.new(private_key, hashAlgo=SHA256).decrypt(ciphertext)


def exercise():
    """Input: message and RSA key size. Generate keys and perform RSA-OAEP round trip.
    Output: public parameters, ciphertext and verified recovered text.
    """
    text = ask_text("Message", "Asymmetric Encryption")
    bits = ask_int("RSA key bits", 2048, 2048, 4096)
    key = RSA.generate(bits)
    ciphertext = rsa_encrypt(key.publickey(), text.encode())
    recovered = rsa_decrypt(key, ciphertext)
    print("n:", key.n, "e:", key.e, "Ciphertext:", ciphertext.hex())
    print("Recovered:", recovered.decode(), "Verified:", recovered == text.encode())


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
